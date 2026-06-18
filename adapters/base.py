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

    def required_env_vars(self) -> list[str]:
        """이 어댑터가 실제로 타깃에 도달하려면 필요한 환경변수 목록.

        스캐너가 스캔 전 preflight 검사에 사용한다. 키가 없으면 "조용한 0"
        (호출은 실패했는데 결함 0건이라 '안전'으로 오인) 대신 명확히 에러로
        종료시키기 위함이다. 기본값: 없음.
        """
        return []
