# First-time GCP onboarding

Use this only when a deployment is blocked because the user does not yet have
an account, billing-enabled project, or long-lived domain. Ask for one blocking
decision or browser action at a time, wait for completion, then continue.

Use plain product language: Google Cloud account, project, billing, domain,
server, fixed IP, DNS, machine size, and monthly cost. Explain a technical term
in one sentence only when the user must recognize it on a Google Cloud page.

## Account and project

1. If deployer authentication or a verified project already exists, skip account
   signup. Otherwise ask whether the user can sign in to Google Cloud. New users
   can open [Google Cloud signup](https://cloud.google.com/free). Let Google
   collect identity, phone, payment, and verification information directly;
   never ask the user to paste any of it into chat.
2. If the user has not selected a project, open the
   [project selector](https://console.cloud.google.com/projectselector2/home/dashboard)
   and ask them to choose an existing project or create one. Then ask only for
   its project ID; verify its immutable project number through the deployer.
3. If billing is not enabled, open the
   [Cloud Billing page](https://console.cloud.google.com/billing) and ask the
   user to link the selected project to an active billing account. Do not ask
   for payment details. Stop until project inspection proves billing is enabled.

## Domain choice

Use a real long-lived domain because changing it later creates a different
Dirextalk server identity.

1. If the user already supplied a domain, confirm that exact name and continue.
2. Otherwise ask whether they already own a domain. Users can review domains in
   the current Google Cloud account on the
   [Cloud Domains page](https://console.cloud.google.com/net-services/domains/registrations/list).
   Present only domain names the user reports or that authenticated tooling can
   safely enumerate, and ask which one to use. Never infer ownership from public
   DNS alone.
3. If the user needs a domain, direct them to
   [Register a domain in Cloud Domains](https://cloud.google.com/domains/docs/register-domain)
   and the Cloud Domains page above. Registration and renewal are separately
   billed and must be completed by the user in Google's UI. If Cloud Domains is
   unavailable for the desired suffix or account, the user may use another
   registrar and return with the domain name.
4. After the domain is selected, inspect public Cloud DNS managed zones in the
   authenticated project. A matching zone means the deployer manages the exact
   deployment A record automatically. The user can review zones on the
   [Cloud DNS zones page](https://console.cloud.google.com/net-services/dns/zones)
   and Google's [managed-zone guide](https://cloud.google.com/dns/docs/zones).
   If no matching zone exists, finish creating the server and fixed IP, then ask
   the user for only one external DNS action: `<domain>  A  <fixed-ip>`.

Do not use localhost, raw IP addresses, wildcard domains, disposable domains,
or temporary wildcard-DNS services as a production identity.
