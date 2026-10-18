import asyncio
import random
import uuid
from typing import Optional

# Added missing imports based on code usage
from dataclasses import dataclass

@dataclass
class SessionContext:
    entity_id: str
    session_id: str
    intent: str
    history: str
    anomalies: list
    simulation: bool

SCENARIOS = {
    "legitimate": {
        "weight": 70,
        "intents": ["health_check", "sync", "data_read"],
        "history": "known_good",
        "anomalies": []
    },
    "suspicious": {
        "weight": 20,
        "intents": ["port_scan", "auth_attempt"],
        "history": "unknown",
        "anomalies": ["high_rate"]
    },
    "malicious": {
        "weight": 10,
        "intents": ["exploit", "data_exfil"],
        "history": "known_bad",
        "anomalies": ["syn_flood_rate>100/s", "ports_probed>500"]
    }
}

class SimulationEngine:
    def __init__(self, trust_engine, sentinel):
        self.trust_engine = trust_engine
        self.sentinel = sentinel
        self.active = False
        self._task: Optional[asyncio.Task] = None
        self.verdicts_generated = 0
        self._lock = asyncio.Lock()

    async def start(self):
        async with self._lock:
            if self.active:
                return
            self.active = True
            self._task = asyncio.create_task(
                self._loop(),
                name="simulation-loop"
            )

    async def stop(self):
        async with self._lock:
            self.active = False
            if self._task and not self._task.done():
                self._task.cancel()
                try:
                    await asyncio.wait_for(
                        self._task, timeout=5.0
                    )
                except (asyncio.CancelledError,
                        asyncio.TimeoutError):
                    pass
                self._task = None

    async def toggle(self) -> bool:
        if self.active:
            await self.stop()
            return False
        await self.start()
        return True

    async def run_once(self, scenario: str = "legitimate") -> dict:
        sc = SCENARIOS.get(scenario, SCENARIOS["legitimate"])
        ctx = SessionContext(
            entity_id=f"sim-{scenario}-{uuid.uuid4().hex[:8]}",
            session_id=f"sess-sim-{uuid.uuid4().hex[:8]}",
            intent=random.choice(sc["intents"]),
            history=sc["history"],
            anomalies=sc["anomalies"],
            simulation=True,
        )
        
        # Need to convert ctx to dict because our current HybridTrustEngine expects a dict
        ctx_dict = {
            "entity_id": ctx.entity_id,
            "session_id": ctx.session_id,
            "intent": ctx.intent,
            "history": ctx.history,
            "anomalies": ctx.anomalies,
            "simulation": ctx.simulation
        }
        
        verdict = await self.trust_engine.evaluate(ctx_dict)
        self.verdicts_generated += 1
        # Nudge GC every 50 verdicts
        import gc
        if self.verdicts_generated % 50 == 0:
            gc.collect()
        return {
            "scenario":   scenario,
            "entity_id":  ctx.entity_id,
            "verdict":    verdict.verdict,
            "confidence": verdict.confidence,
            "reason":     verdict.reason,
        }

    async def _loop(self):
        weights = [s["weight"] for s in SCENARIOS.values()]
        names   = list(SCENARIOS.keys())
        while self.active:
            try:
                scenario = random.choices(
                    names, weights=weights, k=1
                )[0]
                # Run inline — NEVER create a sub-task here
                await self.run_once(scenario)
                await asyncio.sleep(5.0)
            except asyncio.CancelledError:
                break
            except Exception as e:
                import structlog
                structlog.get_logger().error(
                    "sim_loop_error", error=str(e)
                )
                await asyncio.sleep(2.0)
