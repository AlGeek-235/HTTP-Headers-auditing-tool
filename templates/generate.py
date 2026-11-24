from jinja2 import Environment, FileSystemLoader
import weasyprint
from pathlib import Path

def generator(summary) :
    Base_folder = Path(__file__).resolve().parent
    temp_folder = Base_folder
    loaded_tmp = FileSystemLoader(temp_folder)
    env = Environment(loader=loaded_tmp, autoescape=True)
    template = env.get_template("template.html")
    html = template.render(summary)

    report_folder = Path.home() / "Downloads" / "rapport.pdf"
    weasyprint.HTML(string=html).write_pdf(report_folder)
    print("Report created successfully and stored into the Downloads folder of your computer!")
