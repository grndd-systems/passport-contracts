import { Deployer, Reporter } from "@solarity/hardhat-migrate";
import { deployProxy } from "./helpers";

import {
  KYCRegistry__factory,
  StateKeeperMock__factory,
  Registration2Mock__factory,
  TD3QueryProofNoirVerifier__factory,
  TD1QueryProofNoirVerifier__factory,
} from "@ethers-v6";

export = async (deployer: Deployer) => {
  const stateKeeper = await deployer.deployed(StateKeeperMock__factory, "StateKeeper Proxy");
  const registration = await deployer.deployed(Registration2Mock__factory, "Registration2 Proxy");

  // Deploy verifiers for passport (TD3) and ID card (TD1)
  const td3Verifier = await deployer.deploy(TD3QueryProofNoirVerifier__factory, {
    name: "TD3QueryProofNoirVerifier",
  });
  const td1Verifier = await deployer.deploy(TD1QueryProofNoirVerifier__factory, {
    name: "TD1QueryProofNoirVerifier",
  });

  // Deploy KYC contract with TD3 verifier (passport)
  const kyc = await deployProxy(deployer, KYCRegistry__factory, "KYCRegistry");

  // Default citizenship mask
  const defaultCitizenshipMask = 110455744045184552540661350225847617777248319215128571268892831512526848n;
  // Default selector bitfield: 0x21000 (0b100001000000000000)
  // bit 12 - passport expiration lowerbound
  // bit 17 - verify citizenship mask as a blacklist
  const defaultSelector = 0x21000n;
  // Default minimum KYC term: 90 days in seconds
  const defaultMinKycTerm = 90n * 24n * 60n * 60n; // 7776000 seconds

  await kyc.initialize(
    await stateKeeper.getAddress(),
    await registration.getAddress(),
    await td3Verifier.getAddress(),
    await td1Verifier.getAddress(),
    defaultCitizenshipMask,
    defaultSelector,
    defaultMinKycTerm
  );

  Reporter.reportContracts(
    ["KYCRegistry", `${await kyc.getAddress()}`],
    ["TD3QueryProofNoirVerifier", `${await td3Verifier.getAddress()}`],
    ["TD1QueryProofNoirVerifier", `${await td1Verifier.getAddress()}`],
  );
};
