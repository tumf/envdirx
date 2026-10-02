## REMOVED Requirements

### Requirement: Init creates an external key pointer safely
Reason: User removed init; mkdir and keygen provide creation. Existing regular-text pointers remain supported by Fixed external private key reference.

#### Scenario: Creation without init
- **WHEN** new keys are needed
- **THEN** mkdir/keygen replace init and previously generated text pointers remain readable
