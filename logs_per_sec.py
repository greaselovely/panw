import csv
from collections import defaultdict
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import os
from getpass import getpass
from pan.xapi import PanXapi
import xmltodict
import logging
import time

# Set up logging
logging.basicConfig(filename='palo_alto_script.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

import re

def submit_log_job(api):
    try:
        # Submit the log query job
        api.log(log_type="traffic", nlogs="100")
        result = api.xml_result()
        
        # Save raw response to file
        with open('raw_response.txt', 'w') as f:
            f.write(result)
        logging.info("Raw response saved to 'raw_response.txt'")
        
        # Use regex to find the job ID
        match = re.search(r'<job>(.*?)</job>', result)
        if match:
            job_id = match.group(1)
            logging.info(f"Log query job submitted. Job ID: {job_id}")
            return job_id
        else:
            logging.error("Failed to extract job ID from response")
            return None
    except Exception as e:
        logging.error(f"Error submitting log job: {str(e)}")
        logging.error(f"Exception details: {type(e).__name__}, {str(e)}")
        return None

def get_traffic_logs(api, max_retries=5):
    job_id = submit_log_job(api)
    if job_id is None:
        logging.error("Failed to submit log job")
        return None

    logging.info(f"Log query job submitted. Job ID: {job_id}")

    # Add a short delay to allow the job to process
    time.sleep(5)

    for attempt in range(max_retries):
        try:
            logging.info(f"Attempting to retrieve job results (attempt {attempt + 1}/{max_retries})")
            api.log(jobid=job_id)
            result = api.xml_result()
            
            logging.debug(f"Raw job result response: {result[:500]}...")  # Log first 500 characters
            
            # Check if the result contains log entries
            if '<entry' in result:
                logging.info("Successfully retrieved log data")
                return result
            else:
                logging.warning("Retrieved result does not contain log data. Retrying...")
        except Exception as e:
            logging.error(f"Error retrieving job results: {str(e)}")
        
        time.sleep(10)

    logging.error("Max retries reached. Unable to retrieve log data.")
    return None

def check_job_status(api, job_id):
    try:
        api.op(cmd=f"<show><jobs><id>{job_id}</id></jobs></show>")
        response = api.xml_result()
        
        logging.debug(f"Raw job status response: {response}")
        
        root = ET.fromstring(response)
        status = root.find('.//status')
        
        if status is not None:
            return status.text
        else:
            logging.error("Status element not found in job status response")
            return None
    except Exception as e:
        logging.error(f"Error checking job status: {str(e)}")
        return None

def get_job_results(api, job_id):
    try:
        api.log(action="get", jobid=job_id)
        xml_result = api.xml_result()
        
        logging.debug(f"Raw job results response: {xml_result[:500]}...")  # Log first 500 characters
        
        return xml_result
    except Exception as e:
        logging.error(f"Error retrieving job results: {str(e)}")
        return None

def parse_traffic_logs(log_text):
    logs = []
    entries = re.findall(r'<entry.*?</entry>', log_text, re.DOTALL)
    for entry in entries:
        log = {}
        for field in ['receive_time', 'type', 'subtype']:
            match = re.search(f'<{field}>(.*?)</{field}>', entry)
            if match:
                log[field] = match.group(1)
        logs.append(log)
    return logs

def save_logs_to_csv(logs, filename):
    if not logs:
        print("No logs to save.")
        return

    fieldnames = logs[0].keys()
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for log in logs:
            writer.writerow(log)
    print(f"Logs saved to {filename}")

def parse_time(time_str):
    return datetime.strptime(time_str, "%Y/%m/%d %H:%M:%S")

def round_to_15_min(dt):
    return dt - timedelta(minutes=dt.minute % 15, seconds=dt.second, microseconds=dt.microsecond)

def process_logs(logs):
    log_data = defaultdict(lambda: defaultdict(int))
    start_time = None
    end_time = None
    log_types = set()

    for log in logs:
        try:
            time = parse_time(log['receive_time'])
            if start_time is None or time < start_time:
                start_time = time
            if end_time is None or time > end_time:
                end_time = time

            rounded_time = round_to_15_min(time)
            log_type = log['type']
            log_data[rounded_time]['total'] += 1
            log_data[rounded_time][log_type] += 1
            log_types.add(log_type)
        except (ValueError, KeyError):
            continue  # Ignore errors in log entries

    return log_data, start_time, end_time, log_types

def calculate_averages(logs, interval_seconds=900):
    averages = defaultdict(lambda: defaultdict(float))
    for time, counts in logs.items():
        for log_type, count in counts.items():
            averages[time][log_type] = count / interval_seconds
    return averages

def plot_averages(averages, log_types, output_file):
    times = sorted(averages.keys())
    total_avg = [averages[t]['total'] for t in times]

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(times, total_avg, label='Total', alpha=0.7)

    bottom = [0] * len(times)
    for log_type in sorted(log_types):
        type_avg = [averages[t][log_type] for t in times]
        ax.bar(times, type_avg, bottom=bottom, label=log_type, alpha=0.7)
        bottom = [b + ta for b, ta in zip(bottom, type_avg)]

    ax.set_xlabel('Time')
    ax.set_ylabel('Average Logs per Second')
    ax.set_title('Average Logs per Second (15-minute intervals)')
    ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left')

    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_file, bbox_inches='tight')
    print(f"Graph saved as {output_file}")

def main():
    log_file = "palo_alto_logs.csv"
    
    logging.info("Script started")

    if os.path.exists(log_file):
        use_existing = input(f"Existing log file '{log_file}' found. Use it? (y/n): ").lower() == 'y'
    else:
        use_existing = False

    if not use_existing:
        hostname = input("Enter Palo Alto NGFW hostname or IP: ")
        username = input("Enter username: ")
        password = getpass("Enter password: ")

        try:
            logging.info(f"Connecting to Palo Alto NGFW at {hostname}")
            api = PanXapi(hostname=hostname, api_username=username, api_password=password)
            
            logging.info("Retrieving traffic logs")
            xml_logs = get_traffic_logs(api)
            if xml_logs is None:
                logging.error("Failed to retrieve logs. Exiting.")
                return

            logging.info("Parsing traffic logs")
            logs = parse_traffic_logs(xml_logs)
            if not logs:
                logging.error("No logs parsed. Exiting.")
                return

            logging.info(f"Saving logs to {log_file}")
            save_logs_to_csv(logs, log_file)
        except Exception as e:
            logging.error(f"Error connecting to Palo Alto NGFW: {str(e)}")
            return
    else:
        logging.info(f"Using existing log file: {log_file}")
        with open(log_file, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            logs = list(reader)

    logging.info("Processing logs")
    log_data, start_time, end_time, log_types = process_logs(logs)

    if start_time is None or end_time is None:
        logging.error("No valid data found in the logs.")
        return

    logging.info(f"Detected log types: {', '.join(sorted(log_types))}")

    # Limit to 24-hour period
    end_time = min(end_time, start_time + timedelta(days=1))

    # Fill in missing 15-minute intervals
    current_time = start_time
    while current_time <= end_time:
        rounded_time = round_to_15_min(current_time)
        if rounded_time not in log_data:
            log_data[rounded_time] = defaultdict(int)
        current_time += timedelta(minutes=15)

    logging.info("Calculating averages")
    averages = calculate_averages(log_data)

    print("\nAverage logs per second for each 15-minute interval:")
    for time, avg in sorted(averages.items()):
        print(f"{time}: Total: {avg['total']:.2f}, " + ", ".join(f"{k}: {v:.2f}" for k, v in avg.items() if k != 'total'))

    output_file = "log_analysis.png"
    logging.info(f"Plotting averages and saving to {output_file}")
    plot_averages(averages, log_types, output_file)

    logging.info("Script completed successfully")

if __name__ == "__main__":
    main()