import argparse
import requests
import sys
import os


def main():
    parser = argparse.ArgumentParser(
        description="Client for IDA-NO-MCP Analysis Service"
    )
    parser.add_argument(
        "-H", "--host", default="127.0.0.1", help="Server Host IP (default: 127.0.0.1)"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=9753, help="Server Port (default: 9753)"
    )
    parser.add_argument(
        "-i", "--input", required=True, help="Path to input binary file"
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Path to save output ZIP file (default: <input>_analysis.zip)",
    )

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    # Determine output path if not provided
    if not args.output:
        base_name = os.path.basename(args.input)
        args.output = f"{base_name}_analysis.zip"

    url = f"http://{args.host}:{args.port}/analyze"
    print(f"[*] Sending {args.input} to {url}...")

    try:
        with open(args.input, "rb") as f:
            files = {"file": f}
            # stream=True is good for large files
            response = requests.post(url, files=files, stream=True)

        if response.status_code == 200:
            with open(args.output, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"[+] Analysis complete! Saved to: {args.output}")
        else:
            print(f"[!] Server returned error code: {response.status_code}")
            try:
                error_data = response.json()
                print(f"[!] Error details: {error_data}")
            except:
                print(f"[!] Response text: {response.text[:500]}")

    except requests.exceptions.ConnectionError:
        print(f"[!] Could not connect to server at {url}. Is it running?")
    except Exception as e:
        print(f"[!] An error occurred: {str(e)}")


if __name__ == "__main__":
    main()
