import ast
import json
from pathlib import Path
from typing import Optional


CATEGORY_BY_FILE = {
    "test_injection_detector.py": "injection",
    "test_abuse_detector.py": "abuse",
    "test_pii_detector.py": "pii",
    "test_secrets_detector.py": "secrets",
    "test_unsafe_content_detector.py": "unsafe_content",
}


def _string_from_call_arg(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            if isinstance(node.right, ast.Constant) and isinstance(node.right.value, int):
                return node.left.value * node.right.value
    return None


def _extract_case_from_function(
    file_path: Path,
    category: str,
    fn: ast.FunctionDef,
    case_index: int,
) -> list[dict]:
    """Extract benchmark cases from patterns:
      result = agent.run("...")
      assert result.threat_found is True/False
    """
    cases = []
    run_text = None

    for stmt in fn.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if isinstance(target, ast.Name) and target.id == "result":
                call = stmt.value
                if isinstance(call, ast.Call):
                    func = call.func
                    if (
                        isinstance(func, ast.Attribute)
                        and isinstance(func.value, ast.Name)
                        and func.value.id == "agent"
                        and func.attr == "run"
                        and call.args
                    ):
                        run_text = _string_from_call_arg(call.args[0])
        if isinstance(stmt, ast.Assert) and run_text is not None:
            test_expr = stmt.test
            # result.threat_found is True/False
            if (
                isinstance(test_expr, ast.Compare)
                and isinstance(test_expr.left, ast.Attribute)
                and isinstance(test_expr.left.value, ast.Name)
                and test_expr.left.value.id == "result"
                and test_expr.left.attr == "threat_found"
                and len(test_expr.ops) == 1
                and isinstance(test_expr.ops[0], ast.Is)
                and len(test_expr.comparators) == 1
                and isinstance(test_expr.comparators[0], ast.Constant)
                and isinstance(test_expr.comparators[0].value, bool)
            ):
                expected_threat = test_expr.comparators[0].value
                cases.append(
                    {
                        "id": f"{file_path.stem}:{fn.name}:{case_index + len(cases)}",
                        "source_file": file_path.name,
                        "function_name": fn.name,
                        "category": category,
                        "direction": "input",
                        "text": run_text,
                        "label": "threat" if expected_threat else "clean",
                    }
                )
                run_text = None
    return cases


def extract_cases_from_file(file_path: Path) -> list[dict]:
    category = CATEGORY_BY_FILE.get(file_path.name)
    if not category:
        return []

    tree = ast.parse(file_path.read_text(encoding="utf-8"))
    cases = []
    case_index = 0
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            for class_item in node.body:
                if isinstance(class_item, ast.FunctionDef):
                    extracted = _extract_case_from_function(file_path, category, class_item, case_index)
                    cases.extend(extracted)
                    case_index += len(extracted)
    return cases


def write_jsonl(cases: list[dict], output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for case in cases:
            handle.write(json.dumps(case, ensure_ascii=True) + "\n")


def main():
    root = Path(__file__).resolve().parents[1]
    tests_dir = root / "tests"
    files = [tests_dir / file_name for file_name in CATEGORY_BY_FILE]
    all_cases = []
    for file_path in files:
        if file_path.exists():
            all_cases.extend(extract_cases_from_file(file_path))

    # Deterministic ordering
    all_cases = sorted(all_cases, key=lambda item: (item["source_file"], item["function_name"], item["id"]))

    output = root / "datasets" / "benchmark_from_tests.jsonl"
    write_jsonl(all_cases, output)
    print(f"Saved {len(all_cases)} cases to {output}")


if __name__ == "__main__":
    main()
