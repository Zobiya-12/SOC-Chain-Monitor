require("@nomicfoundation/hardhat-ethers");

// Secrets come from environment variables - never write a private key in this file.
//   SEPOLIA_RPC_URL       e.g. an Alchemy / Infura / public Sepolia endpoint
//   DEPLOYER_PRIVATE_KEY  0x-prefixed key of a THROWAWAY testnet wallet
const networks = {
  localhost: { url: "http://127.0.0.1:8545" },
};
if (process.env.SEPOLIA_RPC_URL && process.env.DEPLOYER_PRIVATE_KEY) {
  networks.sepolia = {
    url: process.env.SEPOLIA_RPC_URL,
    accounts: [process.env.DEPLOYER_PRIVATE_KEY],
    chainId: 11155111,
  };
}

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.24",
  networks,
};
