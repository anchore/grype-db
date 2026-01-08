#!/usr/bin/env python3
import argparse
import os
import ast
import sys
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_providers():
    output = os.environ.get("PROVIDERS_USED", None)
    if not output:
        print("invoking grype-db to get list of providers to use")
        result = subprocess.run(
            "make show-providers",
            shell=True, check=True,
            stdout=subprocess.PIPE, stderr=sys.stderr
        )
        output = result.stdout.decode()
    else:
        print("using values from $PROVIDERS_USED environment variable")

    # why in the world would we use ast instead of JSON?!
    # short answer: python borks when there are strings with single quotes instead of double quotes
    return ast.literal_eval(output)


def download_provider(provider: str, status: dict, lock: threading.Lock, verbose: bool) -> tuple[str, bool, str]:
    """Download and restore a single provider's cache. Returns (provider, success, message)."""
    with lock:
        status[provider] = "downloading"

    try:
        if verbose:
            subprocess.run(
                f"make download-provider-cache provider={provider}",
                shell=True, check=True,
            )
        else:
            subprocess.run(
                f"make download-provider-cache provider={provider}",
                shell=True, check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
        with lock:
            status[provider] = "done"
        return (provider, True, "success")

    except subprocess.CalledProcessError as e:
        with lock:
            status[provider] = "failed"
        return (provider, False, str(e))


def progress_reporter(status: dict, lock: threading.Lock, stop_event: threading.Event, total: int):
    """Periodically report progress of downloads."""
    while not stop_event.is_set():
        time.sleep(5)
        if stop_event.is_set():
            break

        with lock:
            done = sum(1 for s in status.values() if s == "done")
            failed = sum(1 for s in status.values() if s == "failed")
            in_progress = [p for p, s in status.items() if s == "downloading"]

        completed = done + failed
        if in_progress:
            print(f"[progress] {completed}/{total} complete, downloading: {', '.join(sorted(in_progress))}")


def main():
    parser = argparse.ArgumentParser(description="Download and restore all provider caches")
    default_verbose = os.environ.get("CI", "").lower() == "true"
    parser.add_argument("-v", "--verbose", action="store_true", default=default_verbose, help="Show all output interleaved (default: true in CI)")
    args = parser.parse_args()

    providers = get_providers()
    print(f"providers: {providers}")

    status = {}
    lock = threading.Lock()
    stop_event = threading.Event()

    # start progress reporter thread
    reporter = threading.Thread(
        target=progress_reporter,
        args=(status, lock, stop_event, len(providers)),
        daemon=True
    )
    reporter.start()

    failed = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(download_provider, p, status, lock, args.verbose): p for p in providers}

        for future in as_completed(futures):
            provider, success, message = future.result()
            if success:
                print(f"[OK] {provider}")
            else:
                print(f"[FAIL] {provider}: {message}")
                failed.append(provider)

    # stop the progress reporter
    stop_event.set()
    reporter.join(timeout=1)

    if failed:
        print(f"\nFailed providers: {failed}")
        sys.exit(1)

    print(f"\nSuccessfully restored {len(providers)} provider caches")


if __name__ == "__main__":
    main()
