# ChatGPT Gmail Sender Plugin

## Installation

1. **Clone the repository**:
   ```bash
   git clone git@github.com:xiaomizhou616/gmail-sender.git
   ```

2. **Install the required package**:
   Use the `requirements.txt` file for installation:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### 1. Use on ChatGPT

- **Authenticate with your Gmail account**: 
  - For first-time users.

- **Provide the necessary email details**: 
  - Sender
  - Recipient
  - Subject
  - Body

- **Send the email**:
  - Directly from ChatGPT.

### 2. Use for Development

The plugin is deployed on `fly.io`. However, you can deploy it on any other service of your choice. For further development:

- Change the hosted URL `https://your-app-url.com` to your URL.
- Update the following details:
  - `"contact_email": "hello@contact.com"`
  - `"http://example.com/legal-info"`
  
  Make these changes in both `ai-plugin.json` and `openapi.yaml` files.

## License

This project is licensed under the MIT License.