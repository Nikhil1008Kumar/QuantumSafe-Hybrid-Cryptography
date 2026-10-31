"""BB84 simulator invariant tests and probability calibration."""
import math
import unittest
from pathlib import Path
import sys
import numpy as np

sys.path.insert(0, str(Path(__file__).parents[1]))
from bb84 import BB84Config, simulate, expected_qber


class BB84Tests(unittest.TestCase):
    def test_ideal_no_noise_no_eve(self):
        result = simulate(BB84Config(10000, 0, 0, 0, 0.2), 123)
        self.assertEqual(result.estimated_qber, 0)
        self.assertEqual(result.retained_raw_mismatches_diagnostic, 0)
        self.assertEqual(result.received_signals, 10000)
        self.assertEqual(result.publicly_revealed_bits + result.retained_raw_bits,
                         result.sifted_bits)

    def test_full_loss_inconclusive(self):
        result = simulate(BB84Config(1000, 0.3, 0, 1, 0.2), 123)
        self.assertEqual(result.received_signals, 0)
        self.assertEqual(result.sifted_bits, 0)
        self.assertTrue(math.isnan(result.estimated_qber))

    def test_independent_noise(self):
        result = simulate(BB84Config(150000, 0, 0.04, 0, 0.35), 123)
        self.assertLess(abs(result.estimated_qber - 0.04), 0.006)

    def test_full_interception(self):
        result = simulate(BB84Config(150000, 1, 0, 0, 0.4), 456)
        self.assertLess(abs(result.estimated_qber - 0.25), 0.009)

    def test_attack_plus_noise(self):
        p, q0 = 0.4, 0.03
        result = simulate(BB84Config(150000, p, q0, 0, 0.4), 789)
        self.assertLess(abs(result.estimated_qber - expected_qber(p, q0)), 0.009)

    def test_sifted_rate_half_with_independent_loss(self):
        result = simulate(BB84Config(100000, 0.3, 0, 0.2, 0.2), 897)
        self.assertLess(abs(result.sifted_bits / 100000 - 0.4), 0.01)

    def test_seed_reproducible_except_timing(self):
        a = simulate(BB84Config(4000, 0.2, 0.01, 0.1, 0.2), 18)
        b = simulate(BB84Config(4000, 0.2, 0.01, 0.1, 0.2), 18)
        for field in a.__dataclass_fields__:
            if field != 'runtime_ms':
                self.assertEqual(getattr(a, field), getattr(b, field))

    def test_invalid_config_rejected(self):
        for kwargs in [dict(intercept_probability=-0.1),
                       dict(noise_probability=1.1),
                       dict(loss_probability=float('nan')),
                       dict(test_fraction=0),
                       dict(transmitted_signals=0)]:
            with self.assertRaises(ValueError):
                BB84Config(**kwargs)

    def test_random_sample_not_deterministically_first(self):
        # Same model, different seeds => different public QBER due to draws.
        estimates = {simulate(BB84Config(500, 0.4, 0, 0, 0.1), seed).estimated_qber
                     for seed in range(30)}
        self.assertGreater(len(estimates), 2)


if __name__ == '__main__':
    unittest.main()
