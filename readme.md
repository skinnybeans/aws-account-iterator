# AWS Account Iterator

This little script is designed to iterate through all AWS accounts you have access by using SSO

This can be useful if you want to pull down a resource inventory across all your accounts or try to find resources with a particular configuration but not sure which region or account it's in

## Prerequisites

- An AWS account or accounts with Identity Center SSO enabled
- A role that:
  - exists in all accounts you want to access
  - has the same name across those accounts
  - you can access through AWS Identity Center

## Set up

1. Set up a virtual environment

    ```console
    python -m venv .venv
    ```

1. Activate virtual environment

    ```console
    source .venv/bin/activate
    ```

1. Install dependencies

    ```console
    pip install -r requirements.txt
    ```

1. Create a `.env` file and filling in with values appropriate for your AWS setup. Sample values:

    ```bash
    export SSO_REGION ='ap-southeast-2'
    export AWS_ROLE   ='ReadOnlyAccess'
    export START_URL  ='https://my-aws-sso-domain.com/start#/'
    ```

1. Source the .env to add the vars to your environment

    ```console
    source .env
    ```

1. Run the script
  
    ```console
    python main.py
    ```

## Potential problems

1. If you are trying to assume a role in an account and that role doesn't exist, an invalid credentials error will get thrown
1. If you are trying to iterate through a region that is not enabled, same thing will happen.

The script will handle these error gracefully, but can be a source of confusion

## Notes

1. Currently it's very slow to run across a large number of accounts and regions, adding concurrency would help here
1. The core part of logging in, getting the account list, and getting creds could be moved into a module to have better reusability
1. The final output is just dumped to console, but writing to a file may make more sense depending on how many resources you are scraping up
