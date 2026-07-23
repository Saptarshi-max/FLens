from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.domain.entities.scan_result import ScanResult
from app.domain.interfaces.report_generator import ReportGenerator


class HtmlReportGenerator(ReportGenerator):
    """Generate HTML reports from scan results using Jinja2 templates."""

    def __init__(self, template_dir: Path) -> None:
        self._environment = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def generate(self, scan_result: ScanResult, output_path: Path) -> Path:
        template = self._environment.get_template("report.html.j2")
        rendered = template.render(scan_result=scan_result)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return output_path
