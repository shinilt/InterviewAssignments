import json
import numpy as np
from pandas import DataFrame
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def readFile():
    try:
        report_json_file_location = "report.json"
        with open(report_json_file_location, "r") as report_json_file:
            report_json_data = report_json_file.read()
            report_json_file.close()
        return report_json_data
    except Exception as e:
        print("Following error occurred : " + str(e))
#readFile Function ended

def plot_histogram(severity_json):
# plot the histogram
    severity_count = []
    severity_label = []
    for plot_data in severity_json:
    #create lists for matplotlib plotting x-y parameters
        severity_count.append(plot_data['num_vulnerabilities'])
        severity_label.append(plot_data['severity'])

    plt.figure(figsize=(23, 10))
    plt.title('Number of unique vulnerabilities by severity')
    plt.bar(severity_label[:], severity_count[:])
    plt.savefig('bar_chart.png')
#plot_histogram function ended



def filter_data(input_report_dict):
    full_file_list = []
# loop over each dependency file and get the vulnerability info if exist
    for dependency in input_report_dict['dependencies']:
        if 'vulnerabilities' in dependency.keys():
            current_file_name = dependency['fileName']
            for vulnerability in dependency['vulnerabilities']:
                current_file_item = []
                current_file_item.append(vulnerability['name'])
                current_file_item.append(vulnerability['severity'])
                current_file_item.append(current_file_name)
                full_file_list.append(current_file_item)
    return full_file_list
#plot_histogram function ended

# main flow starts here
input_report_dict = json.loads(readFile())
full_file_list = filter_data(input_report_dict)
df_filtered_data = DataFrame (full_file_list,columns=['Vulnerability','Severity','filename'])
# convert all severity values to uppercase for consistency
df_filtered_data['Severity'] = df_filtered_data['Severity'].str.upper()

#variable to hold the answer for question 2
vulnerability_json_data = []

for current_vulnerability in df_filtered_data['Vulnerability'].unique():
    vulnerability_list_item = {}
    vulnerability_list_item['vulnerability_name'] = current_vulnerability
    vulnerability_list_item['severity'] = df_filtered_data[(df_filtered_data.Vulnerability == current_vulnerability)].iloc[0]['Severity']
    vulnerability_list_item['file_names'] = list(df_filtered_data[(df_filtered_data.Vulnerability == current_vulnerability)]['filename'])
    vulnerability_json_data.append(vulnerability_list_item)
print(vulnerability_json_data)

#variable to hold the answer for question 3
severity_json_data = []
severity_type_list = []


#add the severity corresponding to each unique vulnerability to a list
for current_item in vulnerability_json_data:
    severity_type_list.append(current_item['severity'])

#generate the output required for Question 3.
for current_severity in df_filtered_data['Severity'].unique():
    severity_count_item = {}
    severity_count_item['severity'] = current_severity
    severity_count_item['num_vulnerabilities'] = severity_type_list.count(current_severity)
    severity_json_data.append(severity_count_item)

print(severity_json_data)
plot_histogram(severity_json_data)
