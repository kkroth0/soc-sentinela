"""
tests/test_stress.py — Teste de estresse e performance do SOC Sentinel.
Simula carga massiva de CVEs e Notícias para validar otimizações.
"""
import time
import unittest
from unittest.mock import MagicMock

# Mock config before imports
import config
config.MIN_CVSS_SCORE = 0.0

from cve import pipeline as cve_pipeline
from cti import pipeline as cti_pipeline
from core import storage, data_manager
from cti import scorer

class TestStressPerformance(unittest.TestCase):
    def setUp(self):
        storage.init_db()
        self.asset_map = {
            "microsoft:windows": {"clients": ["Vectra"], "aliases": ["win10", "win11"]},
            "cisco:ios": {"clients": ["Vectra"], "aliases": ["catalyst"]},
            "fortinet:fortigate": {"clients": ["Vectra"], "aliases": ["fortios"]}
        }
        # Mocking external calls to focus on internal logic performance
        data_manager.get_asset_map = MagicMock(return_value=self.asset_map)

    def test_scorer_performance(self):
        """Valida a velocidade do novo motor de scoring com 1000 iterações."""
        article = {
            "title": "New zero-day exploit for Microsoft Windows found in the wild",
            "summary": "Threat actors are using a new buffer overflow in win11 to compromise Brazilian banks.",
            "source": "Test",
            "layer": 1
        }
        
        start_time = time.time()
        for _ in range(1000):
            scorer.score_article(article, self.asset_map)
        end_time = time.time()
        
        duration = end_time - start_time
        print(f"\n[PERF] 1000 scorings concluídos em {duration:.4f}s ({(1000/duration):.2f} items/sec)")
        self.assertLess(duration, 1.0, "O scoring está muito lento!")

    def test_regex_accuracy(self):
        """Valida se as novas regex pré-compiladas estão pegando os termos corretamente."""
        article = {"title": "Exploit para Fortigate no Brasil", "summary": "Vulnerabilidade crítica detectada.", "layer": 4}
        score, reasons = scorer.score_article(article, self.asset_map)
        
        # Regional (50) + Ativo (50) + Crítico (50) + L4 (30) = 180
        self.assertGreaterEqual(score, 150)
        self.assertTrue(any("Regional" in r for r in reasons))
        self.assertTrue(any("Ativo" in r for r in reasons))

if __name__ == "__main__":
    unittest.main()
