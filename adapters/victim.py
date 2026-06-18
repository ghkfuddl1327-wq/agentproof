"""victim.py — 기존 victim_agent를 감싸는 어댑터 (회귀 테스트용으로 유지)."""

import victim_agent

from .base import AgentAdapter


class VictimAdapter(AgentAdapter):
    """의도된 시크릿 유출 결함이 있는 희생양 에이전트 어댑터.

    룰이 '유출하는 타깃'을 여전히 잡아내는지 확인하는 회귀 기준선이다.
    """

    def ask(self, user_input: str) -> str:
        return victim_agent.ask_agent(user_input)

    def get_target_name(self) -> str:
        return "victim_agent.ask_agent"

    def required_env_vars(self) -> list[str]:
        return ["GEMINI_API_KEY"]
