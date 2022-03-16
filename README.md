# etsy-polling-lambda

This Lambda function polls Etsy's v3 API for new transactions and saves them to a designated S3 bucket while managing Oauth credentials using DynamoDB.

## Requirements

The below **Repository secrets** are required to allow the github workflows to auto-deploy this Lambda function to your environment upon each code push.

- `AWS_ACCESS_KEY_ID`
- `AWS_REGION`
- `AWS_SECRET_ACCESS_KEY`
- `LAMBDA_FUNCTION_NAME`

The actions are defined in `.github/workflows/uploadToLambda.yml`.

## Overview

This lambda function is intended to routinely poll the Etsy API for transactions and then **do something** upon new orders. In the current state, the function will simply save the order to an S3 bucket. 

The function can be invoked manually if your cli is configured.

```sh
$ aws lambda invoke --function-name EtsyPollingTransactions test.out
```

However, I currently have the function configured for invocation by an **EventBridge** rule running every ~2 hours.

The state of the function and the authentication flow (the Oauth credentials & refresh token) is managed with AWS's **DynamoDB** (key/value database). 

> **NOTE**: The **more secure** way to do this would be using AWS's Secrets Manager, however `DynamoDB` is a much cheaper (albeit less secure) approach. Each "secret" stored in Secrets Manager costs $0.40/month + $0.05 / 10k API calls. It's really the monthly pricing **per secret** that gets me. See pricing details [here](https://aws.amazon.com/secrets-manager/pricing/).