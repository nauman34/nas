from flask import Flask, render_template, request, flash
from scanner import scan_network, scan_target, validate_target

app = Flask(__name__)
app.secret_key = "change-this-before-deployment"

@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    target = ""
    mode = "network"
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        mode = request.form.get("mode", "network")
        try:
            validate_target(target)
            if mode == "network":
                results = scan_network(target)
            else:
                results = scan_target(target)
        except (ValueError, RuntimeError) as exc:
            flash(str(exc), "danger")
    return render_template("index.html", results=results, target=target, mode=mode)

if __name__ == "__main__":
    # Keep this bound to localhost by default. Use a production WSGI server for deployment.
    app.run(host="127.0.0.1", port=5000, debug=False)
