from jinja2 import Environment, DictLoader, select_autoescape


def test_html_autoescape_renders_script_as_text():
    env = Environment(loader=DictLoader({"t.html": "{{ value }}"}), autoescape=select_autoescape(["html", "xml"]))
    out = env.get_template("t.html").render(value="<script>alert(1)</script>")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "<script>" not in out


def test_report_generator_uses_autoescape():
    from src.reporting.generator import ReportGenerator
    gen = ReportGenerator()
    assert bool(gen.env.autoescape) is True
