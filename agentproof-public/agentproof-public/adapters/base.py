"""base.py — 스캐너가 의존하는 타깃 에이전트 추상 인터페이스."""

from abc import ABC, abstractmethod


class AgentAdapter(ABC):
    """검사 대상 에이전트를 감싸는 어댑터 인터페이스.

    스캐너(scan.py)는 구체 구현이 아니라 이 인터페이스에만 의존한다.
    """

    @abstractmethod
    def ask(self, user_input: str) -> str:
        """user_input을 타깃에 보내고 응답 텍스트를 반환한다."""
        raise NotImplementedError

    @abstractmethod
    def get_target_name(self) -> str:
        """리포트에 기록할 타깃 식별자."""
        raise NotImplementedError
