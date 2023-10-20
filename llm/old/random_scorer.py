from arthur_bench.scoring import Scorer
import random
from typing import List, Optional

class RandomScorer(Scorer):
    
    @staticmethod
    def name() -> str:
        return "random_scorer"

    @staticmethod
    def requires_reference() -> bool:
        return False
    
    def run_batch(self, candidate_batch: List[str], reference_batch: Optional[List[str]] = None,
                  input_text_batch: Optional[List[str]] = None, context_batch: Optional[List[str]] = None) -> List[float]:
        scores = []
        for text in candidate_batch:
            scores.append( random.randint(1, 10) )  
        return scores