<!DOCTYPE html>
<html>
	<head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
		<title>{{.Report.Artifact.Repository}}</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-GLhlTQ8iRABdZLl6O3oVMWSktQOp6b7In1Zl3/Jr59b6EGGoI1aFkw7cmDA6j6gD" crossorigin="anonymous">
        <style>
            td.severity-CRITICAL, tr.severity-CRITICAL td, .severity-CRITICAL a:link, .severity-CRITICAL a:visited { background-color: #c33; color: white }
            td.severity-HIGH, tr.severity-HIGH td, .severity-HIGH a:link, .severity-HIGH a:visited { background-color: orange; color: white }
            td.severity-MEDIUM, tr.severity-MEDIUM td, .severity-MEDIUM a:link, .severity-MEDIUM a:visited { background-color: #fd5 }
            table.sortable th:not(.sorttable_sorted):not(.sorttable_sorted_reverse):not(.sorttable_nosort):after { content: " \25B4\25BE" }
        </style>
    </head>
	<body>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script>
        <script src="https://www.kryogenix.org/code/browser/sorttable/sorttable.js"></script>
        <div align="right">Logged in as <a href="/logout">{{.Username}}</a></div>
        <nav><a href="/">namespaces</a>/<a href="/n/{{ .Namespace }}">{{ .Namespace }}</a>/{{.Name}}</nav>
        <h1>{{ .Report.Artifact.Repository }}:{{ .Report.Artifact.Tag }}</h1>
        <h2>Summary</h2>
        <table class="table table-bordered">
            <tr><th>Critical</ht><th>High</ht><th>Medium</ht><th>Low</th><th>Unknown</ht><th>None</th></tr>
            <tr>
                <td class="severity-CRITICAL">{{.Report.Summary.Critical}}</td>
                <td class="severity-HIGH">{{.Report.Summary.High}}</td>
                <td class="severity-MEDIUM">{{.Report.Summary.Medium}}</td>
                <td>{{.Report.Summary.Low}}</td>
                <td>{{.Report.Summary.Unknown}}</td>
                <td>{{.Report.Summary.None}}</td>
            </tr>
        </table>
        <h2>Vulnerabilities</h2>
        <table class="table table-bordered sortable">
        <tr>
            <th>Severity</th>
            <th>Vulnerability ID</th>
            <th>Package</th>
            <th>Installed Version</th>
            <th>Fixed Version</th>
        </tr>
	{{range .Report.Vulnerabilities}}
		<tr class="severity-{{ .Severity }}">
            <td>{{ .Severity }}</td>
            <td><a target="_blank" href="{{ .PrimaryLink }}">{{ .VulnerabilityID }}</a></td>
            <td>{{ .Resource }}</td>
            <td>{{ .InstalledVersion }}</td>
            <td>{{ .FixedVersion }}</td>
        </tr>
	{{else}}
		<tr><td colspan="6">None</td></tr>
	{{end}}
    </table>
	</body>
</html>