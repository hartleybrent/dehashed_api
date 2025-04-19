# dehahsed_apiv2
Menu based search using the new (V2) API from dehashed.com 

To get started, you’ll need a valid Dehashed API key, which you should place in a file called configuration.txt. This key is used for authenticating your requests to the Dehashed API. Note: You'll need to refresh your API key as the V1 key has been depreciated. 

configuration.txt should only contain your API key. No username or other password information. 

When you run the script, you'll be presented with a menu that allows you to search for various types of data (like a domain, name, email, phone number, or a password). If you choose to search for a password, the script will hash it using SHA-256 before sending it to the API.

After choosing what you want to search for, the program will make the request to the Dehashed API and save the results into a CSV file. The file is named based on your search type (e.g., dehashed_**.**_.csv).

There’s also a monitoring tool section that takes advantage of the new features of APIv2. You can add new domains to monitor, view existing tasks, update them, or delete tasks you no longer need. Please note, that dehashed will limit access to some tools based on your subscription.

Output format is .csv for ease of use and data analysis. 
