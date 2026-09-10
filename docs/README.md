# Lonewolf design documentation

This directory is the central home for Lonewolf's design documentation. Start
here to find architecture proposals, decisions, and the evidence behind them.

## Starting brief

Lonewolf is a Rust XMPP server. These priorities guide the design discussion:

- Prioritize performance and a low memory footprint. Evaluate compact stanza
  representations and whether a custom XML parser is justified.
- Use an asynchronous runtime with a thread-per-core execution model. The runtime
  and ownership model remain open.
- Start with a single-node MVP focused on core XMPP. Define its exact protocol
  coverage before implementation.
- Start with local persistent storage. Define repository contracts that can
  support a future backend such as PostgreSQL.
- Account for different extension behaviors, including IQ handling, when defining
  component boundaries. Extension implementations are outside the initial MVP.
- Account for future deployment across multiple nodes, including routing to
  connections owned by another node. Coordination requirements and protocols
  remain open.
- Make the first run and ongoing operation simple. Consider self-signed TLS
  certificates for local setup; certificate trust behavior remains open.
- Leave an administrative UI and WebAssembly extensions for later work.

These are product directions, not an approved implementation design. A custom
parser, storage engine, runtime, and clustering protocol have not been selected.

## Documentation conventions

- Keep all design material under `docs/` and link new documents from this index.
- Give each proposal a descriptive file name and an explicit status:
  `In discussion`, `Accepted`, or `Superseded`.
- Separate agreed requirements from recommendations and unresolved questions.
- Record the alternatives, tradeoffs, and validation criteria behind a decision.
- Cite protocol specifications and dependency documentation where they constrain
  the design.
- Use architecture decision records under `docs/decisions/` when individual
  decisions are ready to record. Create that directory with the first record.

## Discussion order

1. Define the MVP use case, target clients, protocol coverage, and federation
   boundary.
2. Set performance targets and resource limits for representative workloads.
3. Define delivery, ordering, persistence, and failure behavior.
4. Decide connection and account ownership across cores, then evaluate runtimes.
5. Define stanza representation and XML parsing requirements.
6. Define repository operations and transaction boundaries.
7. Define extension categories and the boundaries needed for future remote
   routing and isolated extensions.
8. Define installation, account administration, TLS setup, observability, backup,
   and upgrade behavior.
