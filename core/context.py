"""请求上下文"""

from dataclasses import dataclass
from core.models import Query, Answer, IPList


@dataclass(slots=True)
class Context:
    """DNS查询上下文"""

    query: Query
    answer: Answer | None = None
    # IP候选列表
    ip_list: IPList | None = None
    # 请求标记
    tags: str = "default"
