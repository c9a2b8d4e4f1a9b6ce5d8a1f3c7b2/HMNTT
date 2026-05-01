import json
import os

MAX_REPO = 50
SOURCE_REPO = "hiero-ledger/hiero-mirror-node"
REPO_NAME = "hiero-mirror-node"
run_number = os.environ.get('GITHUB_RUN_NUMBER', '0')

target_scopes = [
    ""
]



def get_cyclic_index(run_number, max_index=100):
    """Convert run number to a cyclic index between 1 and max_index"""
    return (int(run_number) - 1) % max_index + 1


def load_repository_urls():
    """Load repository URLs from repositories.json."""
    repo_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "repositories.json")
    if not os.path.exists(repo_file):
        return []

    try:
        with open(repo_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    return [url for url in data if isinstance(url, str) and url.strip()]


if run_number == "0":
    BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"
else:
    repository_urls = load_repository_urls()
    if repository_urls:
        run_index = get_cyclic_index(run_number, len(repository_urls))
        BASE_URL = repository_urls[run_index - 1]
    else:
        BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"


scope_files = [
    "common/src/main/java/org/hiero/mirror/common/CommonConfiguration.java",
    "common/src/main/java/org/hiero/mirror/common/CommonProperties.java",
    "common/src/main/java/org/hiero/mirror/common/config/HieroPropertiesMigrator.java",
    "common/src/main/java/org/hiero/mirror/common/exception/MirrorNodeException.java",
    "common/src/main/java/org/hiero/mirror/common/util/DatabaseWaiter.java",
    "common/src/main/java/org/hiero/mirror/common/util/DomainUtils.java",
    "common/src/main/java/org/hiero/mirror/common/domain/transaction/RecordFile.java",
    "common/src/main/java/org/hiero/mirror/common/domain/transaction/RecordItem.java",
    "common/src/main/java/org/hiero/mirror/common/domain/transaction/Transaction.java",
    "common/src/main/java/org/hiero/mirror/common/domain/token/Token.java",
    "common/src/main/java/org/hiero/mirror/common/domain/contract/ContractResult.java",
    "importer/src/main/java/org/hiero/mirror/importer/ImporterApplication.java",
    "importer/src/main/java/org/hiero/mirror/importer/ImporterProperties.java",
    "importer/src/main/java/org/hiero/mirror/importer/config/ImporterConfiguration.java",
    "importer/src/main/java/org/hiero/mirror/importer/config/CloudStorageConfiguration.java",
    "importer/src/main/java/org/hiero/mirror/importer/downloader/Downloader.java",
    "importer/src/main/java/org/hiero/mirror/importer/downloader/DownloaderProperties.java",
    "importer/src/main/java/org/hiero/mirror/importer/downloader/NodeSignatureVerifier.java",
    "importer/src/main/java/org/hiero/mirror/importer/downloader/ConsensusValidator.java",
    "importer/src/main/java/org/hiero/mirror/importer/downloader/ConsensusValidatorImpl.java",
    "importer/src/main/java/org/hiero/mirror/importer/downloader/StreamFileNotifier.java",
    "importer/src/main/java/org/hiero/mirror/importer/downloader/record/RecordFileDownloader.java",
    "importer/src/main/java/org/hiero/mirror/importer/downloader/record/RecordDownloaderProperties.java",
    "importer/src/main/java/org/hiero/mirror/importer/downloader/balance/AccountBalancesDownloader.java",
    "importer/src/main/java/org/hiero/mirror/importer/downloader/balance/BalanceDownloaderProperties.java",
    "importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNodeSubscriber.java",
    "importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockFileTransformer.java",
    "importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java",
    "importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockProperties.java",
    "importer/src/main/java/org/hiero/mirror/importer/parser/ParserProperties.java",
    "importer/src/main/java/org/hiero/mirror/importer/parser/StreamFileParser.java",
    "importer/src/main/java/org/hiero/mirror/importer/parser/StreamFileListener.java",
    "importer/src/main/java/org/hiero/mirror/importer/parser/record/RecordFileParser.java",
    "importer/src/main/java/org/hiero/mirror/importer/parser/record/RecordParserProperties.java",
    "importer/src/main/java/org/hiero/mirror/importer/parser/record/RecordStreamFileListener.java",
    "importer/src/main/java/org/hiero/mirror/importer/parser/record/entity/topic/TopicMessageLookupEntityListener.java",
    "importer/src/main/java/org/hiero/mirror/importer/parser/record/transactionhandler/ConsensusCreateTopicTransactionHandler.java",
    "importer/src/main/java/org/hiero/mirror/importer/parser/record/transactionhandler/ConsensusSubmitMessageTransactionHandler.java",
    "importer/src/main/java/org/hiero/mirror/importer/parser/balance/AccountBalanceFileParser.java",
    "importer/src/main/java/org/hiero/mirror/importer/parser/balance/BalanceParserProperties.java",
    "importer/src/main/java/org/hiero/mirror/importer/repository/EntityRepository.java",
    "importer/src/main/java/org/hiero/mirror/importer/repository/TopicMessageRepository.java",
    "importer/src/main/java/org/hiero/mirror/importer/repository/TransactionRepository.java",
    "importer/src/main/java/org/hiero/mirror/importer/repository/ContractResultRepository.java",
    "importer/src/main/java/org/hiero/mirror/importer/reconciliation/BalanceReconciliationService.java",
    "importer/src/main/java/org/hiero/mirror/importer/retention/RetentionJob.java",
    "graphql/src/main/java/org/hiero/mirror/graphql/GraphqlApplication.java",
    "graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java",
    "graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java",
    "graphql/src/main/java/org/hiero/mirror/graphql/service/EntityService.java",
    "graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java",
    "graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java",
    "graphql/src/main/resources/graphql/query.graphqls",
    "grpc/src/main/java/org/hiero/mirror/grpc/GrpcApplication.java",
    "grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java",
    "grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java",
    "grpc/src/main/java/org/hiero/mirror/grpc/controller/NetworkController.java",
    "grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageService.java",
    "grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java",
    "grpc/src/main/java/org/hiero/mirror/grpc/retriever/TopicMessageRetriever.java",
    "grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java",
    "grpc/src/main/java/org/hiero/mirror/grpc/listener/TopicListener.java",
    "grpc/src/main/java/org/hiero/mirror/grpc/listener/CompositeTopicListener.java",
    "grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java",
    "grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java",
    "rest/server.js",
    "rest/config.js",
    "rest/constants.js",
    "rest/accounts.js",
    "rest/balances.js",
    "rest/transactions.js",
    "rest/tokens.js",
    "rest/schedules.js",
    "rest/topicmessage.js",
    "rest/routes/index.js",
    "rest/routes/accountRoute.js",
    "rest/routes/blockRoute.js",
    "rest/routes/contractRoute.js",
    "rest/controllers/accountController.js",
    "rest/controllers/blockController.js",
    "rest/controllers/contractController.js",
    "rest/controllers/tokenController.js",
    "rest/controllers/tokenAllowanceController.js",
    "rest/controllers/cryptoAllowanceController.js",
    "rest/service/entityService.js",
    "rest/service/transactionService.js",
    "rest/service/tokenService.js",
    "rest/service/contractService.js",
    "rest/service/cryptoAllowanceService.js",
    "rest/service/tokenAllowanceService.js",
    "rest/service/nftService.js",
    "rest/service/recordFileService.js",
    "rest/service/fileDataService.js",
    "rest/middleware/requestHandler.js",
    "rest/middleware/responseHandler.js",
    "rest/middleware/responseCacheHandler.js",
    "rest/middleware/requestNormalizer.js",
    "rest/middleware/httpErrorHandler.js",
    "rest/middleware/openapiHandler.js",
    "rest/middleware/metricsHandler.js",
    "rest-java/src/main/java/org/hiero/mirror/restjava/RestJavaApplication.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkService.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicService.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/service/HookService.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceService.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropService.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/repository/EntityRepository.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/repository/TopicRepository.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/repository/TokenAirdropRepository.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/repository/NftAllowanceRepository.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookRepository.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageRepository.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkStakeRepository.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java",
    "rest-java/src/main/java/org/hiero/mirror/restjava/repository/RegisteredNodeRepository.java",
    "monitor/src/main/java/org/hiero/mirror/monitor/MonitorApplication.java",
    "monitor/src/main/java/org/hiero/mirror/monitor/MonitorProperties.java",
    "monitor/src/main/java/org/hiero/mirror/monitor/config/MonitorConfiguration.java",
    "monitor/src/main/java/org/hiero/mirror/monitor/publish/TransactionPublisher.java",
    "monitor/src/main/java/org/hiero/mirror/monitor/publish/PublishProperties.java",
    "monitor/src/main/java/org/hiero/mirror/monitor/subscribe/MirrorSubscriber.java",
    "monitor/src/main/java/org/hiero/mirror/monitor/subscribe/SubscribeProperties.java",
    "monitor/src/main/java/org/hiero/mirror/monitor/subscribe/grpc/GrpcSubscriber.java",
    "monitor/src/main/java/org/hiero/mirror/monitor/subscribe/rest/RestSubscriber.java",
    "monitor/src/main/java/org/hiero/mirror/monitor/health/ImporterLagHealthIndicator.java",
    "monitor/src/main/java/org/hiero/mirror/monitor/health/ReleaseHealthIndicator.java",
    "monitor/src/main/java/org/hiero/mirror/monitor/health/SubscriberHealthIndicator.java",
    "web3/src/main/java/org/hiero/mirror/web3/Web3Application.java",
    "web3/src/main/java/org/hiero/mirror/web3/Web3Properties.java",
    "web3/src/main/java/org/hiero/mirror/web3/config/JacksonConfiguration.java",
    "web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java",
    "web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java",
    "web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java",
    "web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java",
    "web3/src/main/java/org/hiero/mirror/web3/service/ContractExecutionService.java",
    "web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java",
    "web3/src/main/java/org/hiero/mirror/web3/service/ContractStateService.java",
    "web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java",
    "web3/src/main/java/org/hiero/mirror/web3/service/RecordFileService.java",
    "web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java",
    "web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManager.java",
    "web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java",
    "web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java",
    "web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java",
    "web3/src/main/java/org/hiero/mirror/web3/evm/properties/TraceProperties.java",
    "web3/src/main/java/org/hiero/mirror/web3/state/MirrorNodeState.java",
    "web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java",
    "web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java",
    "web3/src/main/java/org/hiero/mirror/web3/repository/ContractResultRepository.java",
    "web3/src/main/java/org/hiero/mirror/web3/repository/TransactionRepository.java",
    "web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java",
    "rosetta/main.go",
    "rosetta/app/config/config.go",
    "rosetta/app/config/types.go",
    "rosetta/app/db/client.go",
    "rosetta/app/db/db.go",
    "rosetta/app/errors/errors.go",
    "rosetta/app/middleware/health.go",
    "rosetta/app/middleware/metrics.go",
    "rosetta/app/middleware/trace.go",
    "rosetta/app/persistence/account.go",
    "rosetta/app/persistence/block.go",
    "rosetta/app/persistence/transaction.go",
    "rosetta/app/services/account_service.go",
    "rosetta/app/services/block_service.go",
    "rosetta/app/services/construction_service.go",
    "rosetta/app/services/mempool_service.go",
    "rosetta/app/services/network_service.go",
    "pinger/main.go",
    "pinger/config.go",
    "pinger/mirror_node_client.go",
    "pinger/sdk_client.go",
    "pinger/transfer.go",
    "pinger/cmd/healthcheck/main.go",
]


target_scopes += [
    "Critical: Network not being able to confirm new transactions (total network shutdown)",
    "Critical: Network partition caused outside of design parameters",
    "Critical: Direct loss of funds",
    "Critical: Unintended permanent freezing of funds",
    "Critical: Any impact caused by Tampering/Manipulating Hashgraph history",

    "High: Temporary freezing of network transactions by delaying one block by 500% or more of the average block time of the preceding 24 hours beyond standard difficulty adjustments",
    "High: Preventing gossip of a transaction or multiple transactions",
    "High: Reorganizing transaction history without direct theft of funds",
    "High: Any impacts caused by Tampering with submitted transactions",
    "High: Authorizing transactions without approval from signers/owners",
    "High: Non-network-based DoS affecting projects with greater than or equal to 25% of the market capitalization on top of the respective layer",

    "Medium: Increasing network processing node resource consumption by at least 30% without brute force actions, compared to the preceding 24 hours",
    "Medium: Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network",
    "Medium: A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk",
    "Medium: Incorrect or missing records exported to mirror nodes",
    "Medium: Impacts caused by griefing with no economic damage to any user on the network",
    "Medium: Theft of unpaid staking rewards",
    "Medium: Modification of transaction fees outside of design parameters"
]


def question_generator(target_file: str) -> str:
    """
    Generate exploit-focused audit questions for one scope file.
    """
    prompt = f"""
Generate exploit-focused security audit questions for `{target_file}` only.

Important: `{target_file}` is in-scope in this  repository and is accessible context.
Do not say the file is missing/inaccessible and do not ask for file content.

Rules:
- Every question must start with `[File: {target_file}]`.
- Use symbols/function names from `{target_file}` when possible.
- Each question must include attacker action, preconditions, trigger, and concrete impact.
- Every question MUST assume the attacker is a user with NO special permissions (unprivileged external user).
- Do not assume admin keys, owner roles, privileged APIs, internal network access, or operator-only controls.
- Only include privileged-access scenarios if they clearly start from a no-permission user path that leads to escalation.
- Focus questions on user without privilege this is very important 
- Focus on the scope solely and only generate questions base on the scope .
- Never return empty; output the maximum valid high-signal set.
- Hard minimum 80 questions; target up to 150.
- Do not generate questions base on the Security.MD file that would result in out of scope and rejected vulnerability 
- Generate question base on the scope provided this is very very important 
- Focus questions in scope if scope is provided 

Note: Think like an attacker with no permission (very important), check Researcher.MD also to get more info.

Output only valid Python (no markdown, no explanations):
questions = [
    "[File: {target_file}] [Function: functionName()] Can an unprivileged external user do X by exploiting Y under Z preconditions, causing concrete impact?",
    "[File: {target_file}] [Function: anotherFunction()] Can a user without permission craft malformed input/path W to bypass check Q and violate invariant R, leading to impact S?",
]
"""
    return prompt


def audit_format(security_question: str) -> str:
    """
    Generate a focused security-audit prompt.
    """
    prompt = f"""# SECURITY AUDIT PROMPT

## Security Question
{security_question}

## Access Rules (Strict)
- In-scope paths referenced by this question exist in this repository and are accessible context.
- Do not claim files are missing/inaccessible.
- Do not ask for file content.
- Do not output repo-navigation/help text.
- Vuln is valid mostly when it requires user with no privileged 

## Mission
Investigate only this question for real, exploitable protocol-security issues in contracts.
Ignore style/refactor/docs issues.



Note: Think like a real attacker in a real world and  check Researcher.MD also to get more info and be smart.


## Validation Gate (all required)
1. Exact in-scope code location (file, function, line range).
2. Clear root cause and failed assumption.
3. Practical exploit path (preconditions -> trigger -> result).
4. Existing checks reviewed and shown insufficient.
5. Concrete impact + realistic likelihood.

## Output (Strict)
If and only if all validation checks pass, output this exact structure:

### Title
[Concise vulnerability title]

### Summary
[2-3 sentence summary]

### Finding Description
[Exact code path, root cause, exploit flow, why checks fail]

### Impact Explanation
[Concrete protocol impact and severity rationale]

### Likelihood Explanation
[Realistic attacker capability, feasibility, repeatability]

### Recommendation
[Specific fix guidance]

### Proof of Concept
[Reproducible steps]

Else output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a short strict-validation prompt for  security claims.
    """
    prompt = f"""#  VALIDATION PROMPT

## Security Claim
{report}


Note: Check the Security.MD and never generate report that would result in out of scope and rejected vulnerability 


## Required Checks (all must pass)
1. Exact file/function/line references.
2. Clear root cause and failed assumption.
3. Realistic exploit flow and why checks fail.
4. Concrete impact and realistic likelihood.

## Output (Strict)
If valid, output:

Audit Report
## Title
## Summary
## Finding Description
## Impact Explanation
## Likelihood Explanation
## Recommendation
## Proof of Concept

Else output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above.
"""
    return prompt


def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for .
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Access Rules (Strict)
- Treat in-scope  files as accessible context.
- Do not claim missing/inaccessible files.
- Do not ask for repository contents.

## Objective
Find whether the same vulnerability class can occur in  in-scope code.
Use the external report as a hint, not as proof.


Note: Check the RESEARCHER.md and think in this actual way 
Note: Check the Security.MD and never generate report that would result in out of scope and rejected vulnerability 

## Method
1. Classify vuln type (auth, accounting, state transition, pricing/rounding, replay, reentrancy, DoS).
2. Map this external report to this protocol and check every scenario in this protocol to find valid vulnerability.
3. Prove root cause with exact file/function/line references.
4. Confirm concrete impact + realistic likelihood.

## Disqualify Immediately
- No reachable attacker-controlled entry path.
- Trusted-role compromise required.
- Theoretical-only issue with no protocol impact.
- Impact or likelihood missing.

## Output (Strict)
If valid analog exists, output:

### Title
### Summary
### Finding Description
### Impact Explanation
### Likelihood Explanation
### Recommendation
### Proof of Concept

If not, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt
