"""Discovery Engines — 5 specialized engines for vulnerability discovery.

ENGINE 1: Coverage-Guided Input Mutation (mutation.py)
ENGINE 2: Differential / Anomaly Detection (anomaly.py)
ENGINE 3: State-Aware Logic-Flaw Hunting (logic.py)
ENGINE 4: Blind OOB Discovery (oob.py)
ENGINE 5: Memory / Parser Edge Cases (parser_stress.py)
"""

from scanner.engines.mutation import MutationEngine
from scanner.engines.anomaly import AnomalyEngine
from scanner.engines.logic import LogicFlawEngine
from scanner.engines.oob import OOBEngine
from scanner.engines.parser_stress import ParserStressEngine

__all__ = [
    'MutationEngine',
    'AnomalyEngine',
    'LogicFlawEngine',
    'OOBEngine',
    'ParserStressEngine',
]
