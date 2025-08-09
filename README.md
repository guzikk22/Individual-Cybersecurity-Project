Project requires pyca/cryptography Python module to run. See https://cryptography.io/en/latest/installation/ for installation instructions.

This project is an implementation of a public-key based repudiable authentication protocol.

Folders 'Alice' and 'Bob' contain files enabling basic functionalities for the protocol. Their contents shouldn't be run directly.

Meanwhile 'Scenario' files make use of those basic functionalities to execute a specific program. They can be run directly from console.
Each of them contain marked CONFIGURATION section in the code, where certain values can be edited to configure their behaviour.

Additionally folder 'EvidenceFabricationProtocol' contains files equivalent to those described above, with the distinction that they implement the imitator/simulation version of the main protocol, which is used to demonstrate main protocol's repudiation properties.

And finally 'RoundTripTest.py' is a simple network latency measuring program, useful to better interpret output of the test scenario.
