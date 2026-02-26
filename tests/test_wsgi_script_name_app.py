from flask import Flask, Response, request

app = Flask(__name__)


@app.route("/return/request/url", methods=["GET", "POST"])
def return_request_url():
    return Response(request.url, content_type="text/plain")
