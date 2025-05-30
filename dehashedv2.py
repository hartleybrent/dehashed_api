#!/usr/bin/env python3

# Brent Hartley
# GNU Public License V3 - June

import requests
import json
import os
import hashlib
import csv

# Load the API key from the config file
# Assumes the key is stored in the first line of 'configuration.txt'
def load_api_key():
    with open('configuration.txt', 'r') as f:
        return f.readline().strip()

API_KEY = load_api_key()

# API endpoint constants
API_URL = 'https://api.dehashed.com/v2/search'
PASSWORD_URL = 'https://api.dehashed.com/v2/search-password'
MONITORING_API_URL = 'https://api.dehashed.com/v2/monitoring/'

# Set up the headers used in the HTTP requests
HEADERS = {
    'Dehashed-Api-Key': API_KEY,
    'Content-Type': 'application/json'
}

# Settings dictionary to hold runtime options
SETTINGS = {
    "de_dupe": False  # Default setting disables de-duplication
}

# Toggle the de-duplication setting interactively
def toggle_deduplication():
    current = SETTINGS["de_dupe"]
    print(f"De-duplication is currently {'ON' if current else 'OFF'}.")
    new_val = input("Would you like to toggle it? (y/n): ").strip().lower()
    if new_val == 'y':
        SETTINGS["de_dupe"] = not current
        print(f"De-duplication is now {'ON' if SETTINGS['de_dupe'] else 'OFF'}.")
    else:
        print("No change made.")

# Get user input for a fielded search and construct the API query
def get_search_input(prompt, field):
    value = input(prompt).strip()
    query = f"{field}:{value}"
    return {
        "query": query,
        "page": 1,
        "size": 100,
        "regex": False,
        "wildcard": False,
        "de_dupe": SETTINGS["de_dupe"]
    }, value

# Format a single entry into a readable plaintext string
def pretty_print_entry(entry):
    output = ["Entry:"]
    for field, values in entry.items():
        if field == "database_name":
            output.append(f"  Database Name: {values}")
        elif isinstance(values, list):
            output.extend([f"  {field}: {val}" for val in values if val])
        elif values:
            output.append(f"  {field}: {values}")
    return "\n".join(output)

# Save search results as JSON to a file
def save_to_json(entries, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=4, ensure_ascii=False)

# Save search results to CSV with optional de-duplication
def save_results_to_csv(entries, label):
    txt_filename = f'dehashed_{label}.csv'
    with open(txt_filename, 'w', newline='', encoding='utf-8') as f:
        if not entries:
            print("No entries to write.")
            return

        all_keys = set()
        for entry in entries:
            all_keys.update(entry.keys())

        fieldnames = sorted(all_keys)
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        seen = set()
        for entry in entries:
            entry_id = json.dumps(entry, sort_keys=True)
            if entry_id in seen:
                continue
            seen.add(entry_id)

            flat_entry = {}
            for key in fieldnames:
                value = entry.get(key)
                if isinstance(value, list):
                    flat_entry[key] = ", ".join(map(str, value))
                else:
                    flat_entry[key] = value or ""
            writer.writerow(flat_entry)

    print(f"Results saved to {txt_filename}")

# Search using a plaintext password by hashing it first (SHA256)
def search_password():
    password_plain = input("Enter the plaintext password to search for: ").strip()
    password_hash = hashlib.sha256(password_plain.encode()).hexdigest()
    print(f"Searching for SHA256 hash: {password_hash}")
    return {
        "sha256_hashed_password": password_hash
    }, f"password_{password_hash}"

# Add a domain to Dehashed monitoring
def add_monitoring_domain():
    domain = input("Enter the domain to monitor (e.g., dehashed.com): ").strip()
    payload = {"domain": domain}
    response = requests.post(f"{MONITORING_API_URL}update-domain", headers=HEADERS, json=payload)
    if response.status_code == 200:
        print(f"Successfully added domain: {domain}")
    else:
        print(f"Error adding domain: {response.status_code}, {response.text}")

# Retrieve and display all current monitoring tasks
def view_monitoring_tasks():
    response = requests.post(f"{MONITORING_API_URL}get-tasks", headers=HEADERS, json={"page": 1})
    if response.status_code == 200:
        data = response.json()
        tasks = data.get("tasks", [])
        if tasks:
            print("Existing monitoring tasks:")
            for task in tasks:
                print(f"ID: {task['id']}, Type: {task['type']}, Value: {task['value']}, Active: {task['active']}")
        else:
            print("No monitoring tasks found.")
    else:
        print(f"Error retrieving tasks: {response.status_code}, {response.text}")

# Update a specific monitoring task by ID
def update_monitoring_task():
    task_id = input("Enter the task ID to update: ").strip()
    value = input("Enter the new value for this task: ").strip()
    payload = {
        "id": task_id,
        "value": value
    }
    response = requests.post(f"{MONITORING_API_URL}update-task", headers=HEADERS, json=payload)
    if response.status_code == 200:
        print(f"Task {task_id} updated successfully.")
    else:
        print(f"Error updating task: {response.status_code}, {response.text}")

# Delete a monitoring task by ID
def delete_monitoring_task():
    task_id = input("Enter the task ID to delete: ").strip()
    payload = {"id": task_id}
    response = requests.post(f"{MONITORING_API_URL}delete-task", headers=HEADERS, json=payload)
    if response.status_code == 200:
        print(f"Task {task_id} deleted successfully.")
    else:
        print(f"Error deleting task: {response.status_code}, {response.text}")

# Menu options for fielded searches
SEARCH_OPTIONS = {
    '1': lambda: get_search_input("Enter a domain to search: ", "domain"),
    '2': lambda: get_search_input("Enter a person's name to search: ", "name"),
    '3': lambda: get_search_input("Enter an email address to search: ", "email"),
    '4': lambda: get_search_input("Enter a telephone number to search: ", "phone"),
    '5': search_password
}

# Menu options for monitoring tasks
MONITORING_OPTIONS = {
    '1': add_monitoring_domain,
    '2': view_monitoring_tasks,
    '3': update_monitoring_task,
    '4': delete_monitoring_task
}

# Main program loop and user menu
def main():
    print("Welcome to Brent's Dark Web scanner of doom. Proceed at your own risk!")

    while True:
        print("\nChoose an option:")
        print("1. Run a search")
        print("2. Monitoring options")
        print("3. Toggle de-duplication setting")
        print("4. Exit")

        mode = input("Enter your choice: ").strip()

        if mode == '1':
            print("What would you like to search for?")
            print("1. Domain")
            print("2. Person")
            print("3. Email address")
            print("4. Telephone number")
            print("5. Password (plaintext)")

            choice = input("Enter the number corresponding to your choice: ").strip()
            if choice not in SEARCH_OPTIONS:
                print("Invalid choice.")
                continue

            payload, label = SEARCH_OPTIONS[choice]()
            url = PASSWORD_URL if choice == '5' else API_URL

            try:
                response = requests.post(url, headers=HEADERS, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    entries = data.get("entries", [])
                    if not entries:
                        print("No entries found.")
                        continue

                    print("How would you like to save the results?")
                    print("1. JSON")
                    print("2. CSV")
                    print("3. Plaintext")
                    format_choice = input("Choose an output format (1-3): ").strip()

                    if format_choice == '1':
                        filename = f"dehashed_{label}.json"
                        save_to_json(entries, filename)
                        print(f"Results saved to {filename}")
                    elif format_choice == '2':
                        save_results_to_csv(entries, label)
                    elif format_choice == '3':
                        txt_filename = f"dehashed_{label}.txt"
                        with open(txt_filename, 'w', encoding='utf-8') as f:
                            for entry in entries:
                                f.write(pretty_print_entry(entry))
                                f.write("\n\n")
                        print(f"Results saved to {txt_filename}")
                    else:
                        print("Invalid format choice.")

                elif response.status_code == 429:
                    print("Rate limit hit: Too many requests.")
                elif response.status_code == 403:
                    print("Check your API key in the config file.")
                else:
                    print(f"Error: {response.status_code}")
                    print(response.text)

            except Exception as e:
                print(f"Exception occurred: {e}")

        elif mode == '2':
            print("Monitoring Menu:")
            print("1. Add domain to monitoring")
            print("2. View current monitoring tasks")
            print("3. Update a monitoring task")
            print("4. Delete a monitoring task")

            monitoring_choice = input("Enter your choice (1–4): ").strip()
            if monitoring_choice in MONITORING_OPTIONS:
                MONITORING_OPTIONS[monitoring_choice]()
            else:
                print("Invalid monitoring choice.")

        elif mode == '3':
            toggle_deduplication()
        elif mode == '4':
            print("Exiting. Goodbye!")
            break
        else:
            print("Invalid selection.")

if __name__ == "__main__":
    main()
