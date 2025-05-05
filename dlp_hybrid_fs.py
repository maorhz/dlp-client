import os
import io
from google.cloud import dlp
from google.api_core.exceptions import GoogleAPIError

# --- Configuration ---
# Replace with your Google Cloud Project ID
project_id = 'YOUR_PROJECT_ID'
# Replace with the full resource name of your DLP Hybrid Job
# Example: 'projects/your-project-id/locations/global/dlpJobs/your-hybrid-job-id'
hybrid_job_name = 'YOUR_HYBRID_JOB_NAME'
# Replace with the path to the directory you want to scan
directory_to_scan = '/path/to/your/directory'
# Optional: List of file extensions to include (e.g., ['.txt', '.csv'])
# If empty, all files will be processed.
include_extensions = [] # Example: ['.txt', '.csv', '.log']
# Maximum file size to process (in bytes). Files larger than this will be skipped.
# DLP API has limits on the size of content that can be sent in a single request.
# Adjust based on your needs and DLP API quotas.
max_file_size_bytes = 1024 * 1024 * 1 # 1 MB limit as an example

# --- Initialize DLP Client ---
# Ensure your GOOGLE_APPLICATION_CREDENTIALS environment variable is set
# to the path of your service account key file.
try:
    dlp_client = dlp.DlpServiceClient()
except Exception as e:
    print(f"Error initializing DLP client: {e}")
    print("Please ensure your GOOGLE_APPLICATION_CREDENTIALS environment variable is set.")
    exit()

# --- Function to send file content to Hybrid Job ---
def send_to_hybrid_job(file_path, content):
    """Sends file content to the specified DLP Hybrid Job for inspection."""
    try:
        # Create the request payload
        request = {
            'name': hybrid_job_name,
            'hybrid_content': {
                'content': content,
                'data_item_mode': dlp.HybridContentItem.BytesType.TEXT, # Or BYTES if not text
                'finding_metadata': {
                    'file_path': file_path,
                    # Add any other relevant metadata about the file
                }
            }
        }

        # Call the DLP API to send the content to the hybrid job
        # Note: The exact method might vary slightly depending on the client library version.
        # This uses the recommended approach for sending to a job.
        response = dlp_client.hybrid_inspect_dlp_job(request)

        print(f"Successfully sent '{file_path}' to Hybrid Job.")
        # The actual findings will be processed and stored by the Hybrid Job configuration
        # You won't see findings directly in this response, but you can check the job status.
        # print(f"API Response: {response}") # Uncomment to see the full API response

    except GoogleAPIError as e:
        print(f"Error sending '{file_path}' to Hybrid Job: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while processing '{file_path}': {e}")


# --- Main Scanning Logic ---
print(f"Starting scan of directory: {directory_to_scan}")

if not os.path.isdir(directory_to_scan):
    print(f"Error: Directory not found or is not a directory: {directory_to_scan}")
    exit()

processed_count = 0
skipped_count = 0

for root, _, files in os.walk(directory_to_scan):
    for file in files:
        file_path = os.path.join(root, file)

        # Check file extension if include_extensions is specified
        if include_extensions and os.path.splitext(file_path)[1].lower() not in include_extensions:
            print(f"Skipping '{file_path}': Extension not in include_extensions list.")
            skipped_count += 1
            continue

        # Check file size
        try:
            file_size = os.path.getsize(file_path)
            if file_size > max_file_size_bytes:
                print(f"Skipping '{file_path}': File size ({file_size} bytes) exceeds limit ({max_file_size_bytes} bytes).")
                skipped_count += 1
                continue
        except OSError as e:
            print(f"Error getting size for '{file_path}': {e}. Skipping.")
            skipped_count += 1
            continue

        # Read file content
        try:
            # Attempt to read as text first, fall back to bytes if encoding error
            with io.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                 content = f.read()
            data_item_mode = dlp.HybridContentItem.BytesType.TEXT

        except Exception: # Catch any reading or encoding error
             try:
                 with open(file_path, 'rb') as f:
                     content = f.read()
                 data_item_mode = dlp.HybridContentItem.BytesType.BYTES
             except Exception as e:
                 print(f"Error reading file '{file_path}': {e}. Skipping.")
                 skipped_count += 1
                 continue

        # Send content to DLP Hybrid Job
        send_to_hybrid_job(file_path, content)
        processed_count += 1

print("-" * 30)
print("Scan Summary:")
print(f"Directories scanned: {processed_count + skipped_count}") # Approximation, counts files processed/skipped
print(f"Files processed: {processed_count}")
print(f"Files skipped (size/extension/error): {skipped_count}")
print("Scan process finished.")

# Note: To view the findings, go to the Google Cloud console, navigate to Sensitive Data Protection,
# and check the details of the Hybrid Job you specified.
