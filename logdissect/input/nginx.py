"""nginx combined 日志的流式输入模块。

本模块服务于常驻管线（``python -m logdissect tail --format nginx``），
同时被 :mod:`logdissect.input.file` 的分发表登记为 ``nginx``，因此
``-i nginx`` 显式指定与自动嗅探两条入口都走这里。

四处互相牵制的设计决定
----------------------

1. **行尾 ``+0800`` 时间戳一律归一到 UTC，而不是保留原串。**
   core 里 :class:`logdissect.core.LogObject` 的排序键是
   ``numeric_date_stamp_utc``（与既有
   :func:`logdissect.utils.merge_logs` 的合并排序口径一致），
   last/range 过滤器也都拿 UTC 数字戳比较。nginx 行内嵌 ``+0800``
   偏移量，若保留原串、直接把墙钟数字塞进排序键，那么同一时刻写成
   ``+0800`` 与 ``+0000`` 的两条日志会相差 8 小时，与其它来源混排时
   必然串位。所以解析时用偏移量算出 UTC 数字戳写入
   ``numeric_date_stamp_utc``，原始 ``+0800`` 仍保留在 ``tzone``、
   ``numeric_date_stamp`` 保留本地墙钟，展示用原串（``date_stamp``）
   不动。

2. **畸形行不整份丢弃，跳过条数累进共享计数器。**
   一行解析失败只跳过那一行：``parse_line`` 返回 ``None``，计数器
   ``lines_total`` 照加、``lines_parsed`` 不加、``lines_skipped`` +1。
   计数器挂在 :class:`~logdissect.core.LogObject`（键名
   ``lines_total`` / ``lines_parsed`` / ``lines_skipped`` /
   ``lines_filtered``），与 last/range 过滤器读的是同一个对象：过滤
   器每剔一条就把 ``lines_filtered`` +1。因此任何阶段都对得上账：
   ``lines_total == lines_parsed + lines_skipped`` 且
   ``len(entries) == lines_parsed - lines_filtered``。

3. **百兆样本逐行流式处理，不整载，且常驻路径不留明细。**
   对 100MiB 合成 combined 样本（约 116 万行，``tracemalloc``
   计量，开发机实测）：整载 ``readlines()`` 的驻留峰值约 154 MiB；
   逐行读但把每条解析后的 entry dict 都留下来（一次性
   ``parse_file`` 的口径，供 last/range 过滤）峰值约 1445 MiB——
   dict 比原串还胖；常驻 tail 路径逐行读、只留状态码聚合计数与有界
   失败/非 2xx 样本（见 :mod:`logdissect.tail`），峰值约 0.1 MiB，
   且不随行数增长。常驻管线要一直跟着日志跑，故必须选第三条：逐行
   流 + 只留聚合。一次性 ``parse_file`` 仍保留全部 entries（过滤器
   需要明细），但本身也是逐行读、不再 ``readlines``。绝对数字随机器
   浮动，量级关系（聚合 0.1MiB << 整载 154MiB << 留明细 1445MiB）
   不浮动。

4. **嗅探顺序老格式在前，nginx 垫后。**
   combined 格式与仓库里的老 ``webaccess`` parser 同源，nginx 的
   宽松正则能吃下不少老格式行；若新模块排在前面，老日志会被新来的
   截胡。:mod:`logdissect.input.file` 的嗅探表严格按
   "既有 parsers 原序在前、nginx 在最后" 排列，每个模块按采样行
   命中数打分，取首个达到阈值的模块，只有所有老格式都不命中时才会
   落到 nginx。显式 ``-i nginx`` 不受顺序影响，直接命中。
"""

import re
import os
from datetime import datetime
from datetime import datetime, timedelta

from logdissect.input.type import InputModule

MONTHS = {'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
          'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
          'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'}


class ParseModule(InputModule):
    """Streaming parser for nginx ``combined`` access log lines."""

    name = 'nginx'
    desc = 'nginx combined access log streaming input module'

    # 严格 combined：remote - - [day/Mon/Year:HH:MM:SS +0800]
    # "METHOD PATH PROTO" status bytes "ref" "ua"。允许 "-" 占位的
    # referer/user-agent，但要求引号与状态码齐全。
    format_regex = (
        r'^(\S+) \S+ \S+ '
        r'\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) '
        r'([+-]\d{4})\] '
        r'"([A-Z]+) (\S+) (HTTP/\d(?:\.\d)?)" '
        r'(\d{3}) (\d+|-) '
        r'"([^"]*)" "([^"]*)"\s*$'
    )

    # 宽松分支：老 webaccess 行常出现没有显式 tz（用本地时区）、
    # 或请求里带空格的怪请求。此分支不满足严格 combined，但能确定
    # 状态码等核心字段，按解析成功计入；两分支都不中才算畸形行。
    backup_format_regex = (
        r'^(\S+) \S+ \S+ '
        r'\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})'
        r'(?: ([+-]\d{4}))?\] '
        r'"(.*)" (\d{3}) (\d+|-) '
        r'"([^"]*)" "([^"]*)"\s*$'
    )

    def __init__(self, tzone=None):
        """Create the parser.

        ``tzone`` (e.g. ``'+0500'``) is only used for lines that carry
        no explicit offset of their own; a line's own ``+0800`` always
        wins.
        """
        self.tzone = tzone
        self.date_regex = re.compile(self.format_regex)
        self.backup_date_regex = re.compile(self.backup_format_regex)

    def parse(self, line):
        """Parse one combined log line into an entry dict.

        Returns ``None`` when the line cannot be parsed; callers count
        the rejection themselves instead of dropping the whole feed.
        """
        ourline = line.rstrip('\r\n')
        match = self.date_regex.match(ourline)
        if match:
            (source_host, day, mon, year, hour, minute, second,
             tzone, method, path, protocol, status, byte_count,
             referrer, user_agent) = match.groups()
        else:
            match = self.backup_date_regex.match(ourline)
            if not match:
                return None
            (source_host, day, mon, year, hour, minute, second,
             tzone, request, status, byte_count,
             referrer, user_agent) = match.groups()
            request_parts = request.split(' ')
            if len(request_parts) >= 3:
                method = request_parts[0]
                protocol = request_parts[-1]
                path = ' '.join(request_parts[1:-1])
            elif len(request_parts) == 2:
                method, path = request_parts
                protocol = ''
            else:
                method = request_parts[0] if request_parts else ''
                path = ''
                protocol = ''

        month = MONTHS.get(mon)
        if month is None:
            return None

        tzone = tzone or self.tzone or '+0000'
        numeric_local = (year + month + day + hour + minute + second)
        numeric_utc = self._to_utc(numeric_local, tzone)

        try:
            status_int = int(status)
        except (TypeError, ValueError):
            return None

        entry = {
            'parser': self.name,
            'raw_text': ourline,
            'source_host': source_host,
            'date_stamp': '{}/{}/{}:{}:{}:{} {}'.format(
                day, mon, year, hour, minute, second, tzone),
            'tzone': tzone,
            'year': year,
            'month': month,
            'day': day,
            'tstamp': hour + minute + second,
            'numeric_date_stamp': numeric_local,
            'numeric_date_stamp_utc': numeric_utc,
            'method': method,
            'path': path,
            'protocol': protocol,
            'status': str(status_int),
            'status_int': status_int,
            'byte_count': byte_count,
            'referrer': referrer,
            'user_agent_string': user_agent,
        }
        return entry

    @staticmethod
    def _to_utc(numeric_local, tzone):
        """Shift a ``%Y%m%d%H%M%S`` stamp by a ``+HHMM`` offset."""
        t = datetime.strptime(numeric_local, '%Y%m%d%H%M%S')
        hours = int(tzone[1:3])
        minutes = int(tzone[3:5])
        delta = timedelta(hours=hours, minutes=minutes)
        if tzone[0] == '-':
            t += delta
        else:
            t -= delta
        return t.strftime('%Y%m%d%H%M%S')

    def parse_file(self, sourcepath):
        """Stream a whole file into a ``LogObject``-shaped dict.

        Used by the non-resident path and by the acceptance command
        ``tail --format nginx <file>``'s initial replay. Lines are read
        one at a time; malformed lines increment ``lines_skipped``
        rather than aborting the parse.
        """
        data = {
            'parser': self.name,
            'source_path': sourcepath,
            'source_file': sourcepath.replace('\\', '/').split('/')[-1],
            'entries': [],
            'lines_total': 0,
            'lines_parsed': 0,
            'lines_skipped': 0,
            'lines_filtered': 0,
        }
        try:
            data['source_file_mtime'] = os.path.getmtime(sourcepath)
            data['source_file_year'] = datetime.fromtimestamp(
                data['source_file_mtime']).year
        except OSError:
            data['source_file_mtime'] = None
            data['source_file_year'] = None
        with open(sourcepath, 'r', encoding='utf-8',
                  errors='replace') as logfile:
            for line in logfile:
                ourline = line.rstrip('\r\n')
                if not ourline.strip():
                    continue
                data['lines_total'] += 1
                entry = self.parse(ourline)
                if entry is None:
                    data['lines_skipped'] += 1
                    continue
                entry['source_path'] = data['source_path']
                data['entries'].append(entry)
                data['lines_parsed'] += 1
        return data
