from collections import defaultdict
import json
import os

reports_base_path = "E:\Academic\Georgia Tech\Projects\ECS\\bridge\\results\\"
# reports_base_path = '/home/shubham/skimmers/reports/local/'

report_paths = [reports_base_path + report_name for report_name in os.listdir(reports_base_path)]


def zero():
    return 0

def sourceDefault():
    return {
        "count": 0,
        "tags": defaultdict(zero),
        "tags_files": defaultdict(zero),
    }

def overviewDefault():
    return {
        "count": 0,
        "sources": defaultdict(sourceDefault),
    }

def getResultsOverview():
    results = defaultdict(overviewDefault)

    for reportPath in report_paths:
        data = ""
        with open(reportPath, 'r') as resFile:
            try:
                data = resFile.read()
            except Exception as e:
                print(reportPath, e)

        data = dict(json.loads(data))
        platform = data["download_platform"]
        results[platform]["count"] += 1
        
        source  = data["download_source"]
        results[platform]["sources"][source]["count"] += 1

        mal_file_info = dict(data["mal_file_info"])

        instance_tags = set()

        for filepath in mal_file_info:
            file_info = dict(mal_file_info[filepath])
            file_sus_tags = list(file_info["suspicious_tags"])
            for _tag in file_sus_tags:
                results[platform]["sources"][source]["tags_files"][_tag] += 1
                instance_tags.add(_tag)

        for _tag in instance_tags:
            results[platform]["sources"][source]["tags"][_tag] += 1

    with open('results_overview.json', 'w') as writefile:
        writefile.write(json.dumps(results, default=str))


if __name__ == "__main__":
    getResultsOverview()