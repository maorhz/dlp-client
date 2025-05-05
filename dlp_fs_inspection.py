import argparse
import io
from google.cloud import dlp_v2

def inspect_file(project_id: str, file_path: str, info_types: list, min_likelihood: str):
    """
    Scans a local file for sensitive data using the Google Cloud DLP API.

    Args:
        project_id: The Google Cloud project ID.
        file_path: The path to the local file to scan.
        info_types: A list of strings representing the infoTypes to look for
                    (e.g., ['EMAIL_ADDRESS', 'PHONE_NUMBER', 'US_SOCIAL_SECURITY_NUMBER']).
        min_likelihood: The minimum likelihood of a match to report ('VERY_UNLIKELY',
                        'UNLIKELY', 'POSSIBLE', 'LIKELY', 'VERY_LIKELY').
    """
    # Instantiate a client
    client = dlp_v2.DlpServiceClient()

    # Read the file content
    try:
        with io.open(file_path, mode='rb') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return

    # Construct the `InspectConfig`
    # This specifies what infoTypes to look for and the minimum likelihood
    inspect_config = {
        "info_types": [{"name": info_type} for info_type in info_types],
        "min_likelihood": min_likelihood,
    }

    # Construct the `ContentItem` with the file data
    # The DLP API can inspect various types of content. For a file, we provide
    # the byte content.
    item = {"byte_item": {"type": "BYTES_TYPE_UNSPECIFIED", "data": content}}

    # Construct the `InspectContentRequest`
    # This includes the project where the request is made, the content to inspect,
    # and the inspection configuration.
    request = {
        "parent": f"projects/{project_id}/locations/global", # Or a specific region
        "inspect_config": inspect_config,
        "item": item,
    }

    print(f"Scanning file: {file_path}")

    # Call the API
    try:
        response = client.inspect_content(request=request)

        # Process and print the findings
        if response.result.findings:
            print(f"Findings in {file_path}:")
            for finding in response.result.findings:
                print(f"  InfoType: {finding.info_type.name}")
                print(f"  Likelihood: {finding.likelihood}")
                # Note: By default, the API does not return the actual sensitive
                # quote. You can configure this in InspectConfig if needed, but
                # be mindful of exposing sensitive data in your logs/output.
                # print(f"  Quote: {finding.quote}")
                if finding.location.byte_range:
                    print(f"  Byte range: {finding.location.byte_range.start}-{finding.location.byte_range.end}")
                if finding.location.codeword_info:
                     print(f"  Codeword info: {finding.location.codeword_info}")
                if finding.location.content_locations:
                    print(f"  Content locations: {finding.location.content_locations}")
                print("-" * 20)
        else:
            print(f"No sensitive data findings in {file_path}")

    except Exception as e:
        print(f"An error occurred during DLP inspection: {e}")


if __name__ == "__main__":
    # Example usage:
    # Create a dummy file for testing
    dummy_file_content = "My email is test@example.com and my phone number is 123-456-7890. My SSN is 999-88-7777."
    dummy_file_path = "test_scan_file.txt"
    with open(dummy_file_path, "w") as f:
        f.write(dummy_file_content)

    # Replace with your Google Cloud project ID
    your_project_id = "your-gcp-project-id" # <--- IMPORTANT: Replace with your project ID

    # Define the infoTypes you want to scan for
    types_to_scan = ["EMAIL_ADDRESS", "PHONE_NUMBER", "US_SOCIAL_SECURITY_NUMBER"]

    # Define the minimum likelihood for findings
    likelihood_threshold = "POSSIBLE"

    # Run the inspection
    inspect_file(your_project_id, dummy_file_path, types_to_scan, likelihood_threshold)

    # Clean up the dummy file (optional)
    import os
    # os.remove(dummy_file_path)
    print(f"Created dummy file: {dummy_file_path}. Remember to delete it manually if not removed by script.")

    # To scan multiple files, you would add logic here to traverse your file system
    # and call inspect_file for each file.
    # Example (simplified):
    # import os
    # directory_to_scan = "/path/to/your/folder"
    # for root, _, files in os.walk(directory_to_scan):
    #     for file in files:
    #         full_file_path = os.path.join(root, file)
    #         inspect_file(your_project_id, full_file_path, types_to_scan, likelihood_threshold)
