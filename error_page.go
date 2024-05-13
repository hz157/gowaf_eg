package gowaf

import (
	"strings"
	"time"
)

func FormatHTML(id string) string {
	datetime := time.Now().Format("2006-01-02 15:04:05")

	htmlTemplate := `<!DOCTYPE html>
	<html>
	<head>
		<title data-react-helmet="true">405 Forbidden for WAF</title>
		<style>
			footer {
				position: fixed;
				bottom: 0;
				width: 100%;
				display: flex;
				justify-content: center;
				align-items: center;
				padding: 10px 0; /* Optional: Adjust padding */
			}	

			body, html {
				padding: 0;
				margin: 0;
				font-family: 'Quicksand', sans-serif;
				font-weight: 400;
				overflow: hidden;
			}

			.container {
				display: -webkit-box;
				display: -ms-flexbox;
				display: flex;
				-webkit-box-align: center;
					-ms-flex-align: center;
						align-items: center;
				-webkit-box-pack: center;
					-ms-flex-pack: center;
						justify-content: center;
				height: 100vh;
				width: 100%;
				-webkit-transition: -webkit-transform .5s;
				transition: -webkit-transform .5s;
				transition: transform .5s;
				transition: transform .5s, -webkit-transform .5s;
			}

			.stack-container {
				position: relative;
				width: 420px;
				height: 210px;
				-webkit-transition: width 1s, height 1s;
				transition: width 1s, height 1s;
			}

			.error {
				width: 400px;
				padding: 40px;
				text-align: center;
			}

			.error h1 {
				font-size: 125px;
				padding: 0;
				margin: 0;
				font-weight: 700;
			}

			.error h2 {
				margin: -30px 0 0 0;
				padding: 0px;
				font-size: 47px;
				letter-spacing: 12px;
			}
		</style>
		<meta charset="utf-8">
	</head>
	<body>
		<div class="container">
			<div class="error">
				<h1>405</h1>
				<h2>error</h2>
				<p>Your access to this website has been blocked by our Web Application Firewall (WAF) due to suspicious activity. Please ensure your system is malware-free and try again.</p>
				<p>id: {{id}}</p>
				<p>datetime: {{datetime}}</p>
			</div>
			<footer>
				<p>&copy; 2023-2024. Powered by <a href="https://github.com/hz157/gowaf">gowaf</a> for detection capability.</p>
			</footer>
		</div>
	</body>
	</html>`

	// 替换模板中的{{id}}和{{datetime}}
	htmlTemplate = strings.Replace(htmlTemplate, "{{id}}", id, 1)
	htmlTemplate = strings.Replace(htmlTemplate, "{{datetime}}", datetime, 1)

	return htmlTemplate
}
