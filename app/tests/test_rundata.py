"""What the console reads from a run folder (app/rundata.py). A run that removed the directions of several layers carries
"layers", and with --combine the scan's combinations from scan.json; a run from before, with "layer" only, reads as it
always did (layers None, no combinations).

    python -m unittest discover -s app/tests
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import rundata  # noqa: E402


def write(folder, name, obj):
    with open(os.path.join(folder, name), "w", encoding="utf-8") as f:
        json.dump(obj, f)


class SeveralLayers(unittest.TestCase):
    def setUp(self):
        self.project = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.project, True)

    def make_run(self, rid, layers=None, combos=None):
        d = os.path.join(self.project, "runs", f"abliterate_{rid}")
        os.makedirs(d)
        prompts = ["p1", "p2"]
        write(d, "layer_analysis.json", {"n_layers": 4, "d_model": 64, "n_inst_train": 8, "harmful_train_examples": ["h"],
                                         "harmless_train_examples": ["s"], "separation_pct": [1, 2, 3, 4], "norms": [1, 1, 1, 1],
                                         "act_size": [1, 1, 1, 1], "similarity": [[1]], "cos_next": [1, None], "peak": 2,
                                         "stable": [2], "scan_range": [1, 3]})
        write(d, "baseline.json", {"prompts": prompts, "baseline": ["I cannot", "I cannot"], "n_base": 2})
        write(d, "scan_results.json", [{"layer": l, "refusals": r, "norm": 1.0, "cjk_ratio": 0.0, "generations": ["a", "b"]}
                                       for l, r in ((2, 0), (1, 1), (3, 1))])
        chosen = layers or [2]
        write(d, "generations.json", {"prompts": prompts, "baseline": ["I cannot", "I cannot"], "layer": chosen[0],
                                      "after_orthogonalization": ["Sure", "Sure"], **({"layers": layers} if layers else {})})
        meta = {"model_repo": "THUDM/glm-edge-1.5b-chat", "slug": "glm-edge-1.5b-chat", "status": "done", "layer": chosen[0],
                "recommended": 2}
        if layers:
            meta.update(layers=layers, recommended_layers=[2, 1])
        write(d, "run.json", meta)
        if combos:
            write(d, "scan.json", {"combine": 3, "combos": combos, "recommended": [2, 1]})
        return d

    def test_a_run_from_before_reads_as_before(self):
        d = self.make_run("20261101_000000")
        (row,) = rundata.list_runs(self.project)
        self.assertEqual((row["layer"], row["layers"], row["recommended"], row["recommended_layers"]), (2, None, 2, None))
        data = rundata.collect(self.project, d)
        self.assertEqual((data["choice"]["layer"], data["choice"]["layers"]), (2, None))
        self.assertIsNone(data["scan"]["combos"])
        self.assertEqual((data["meta"]["layer"], data["meta"]["layers"], data["meta"]["recommended_layers"]), (2, None, None))

    def test_several_layers_and_the_combinations(self):
        combos = [{"layers": [2, 1], "refusals": 0, "cjk": 0.0, "generations": ["x", "y"]},
                  {"layers": [2, 1, 3], "refusals": 0, "cjk": 0.1, "generations": ["x", "z"]}]
        d = self.make_run("20261102_000000", layers=[17, 15, 19], combos=combos)
        (row,) = rundata.list_runs(self.project)
        self.assertEqual((row["layer"], row["layers"], row["recommended_layers"]), (17, [17, 15, 19], [2, 1]))
        data = rundata.collect(self.project, d)
        self.assertEqual((data["choice"]["layer"], data["choice"]["layers"]), (17, [17, 15, 19]))
        self.assertEqual(data["scan"]["combos"], combos)
        self.assertEqual((data["meta"]["layers"], data["meta"]["recommended_layers"]), ([17, 15, 19], [2, 1]))

    def test_choice_from_run_json_before_validation(self):
        # applied without verify (no generations.json yet): the choice comes from run.json, as "layer" always did
        d = self.make_run("20261103_000000", layers=[15, 17])
        os.remove(os.path.join(d, "generations.json"))
        data = rundata.collect(self.project, d)
        self.assertEqual((data["choice"]["layer"], data["choice"]["layers"]), (15, [15, 17]))


if __name__ == "__main__":
    unittest.main()
