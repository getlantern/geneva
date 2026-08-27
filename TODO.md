- [x] Update package-level documentation with README changes
- [x] Do not use strings in switch statements in triggers
- [x] Add tests for TCP triggers
- [x] Add any missing documentation
- [x] Strategies should pass fresh packets to each action tree in a forest
- [x] Feed parsed/validated strategies back in to make sure they're correct
- [x] Handle frag offset of -1
- [x] Revisit some assumptions about packet layout in fragment action
- [x] Deal with triggers that have empty values (empty values are only valid where they denote
  "no data" — `[TCP:load:]` matches packets with no payload and data-less options like
  `[TCP:options-sackok:]` match their option when present; empty values elsewhere are rejected
  with a clear error)
