import { Deployer } from "@solarity/hardhat-migrate";
import { ethers } from "hardhat";

import {
  Registration2Mock__factory,
  NoirRegisterIdentity_2_256_3_6_576_248_1_2432_3_256__factory,
} from "@ethers-v6";

import { Z_NOIR_PASSPORT_2_256_3_6_576_248_1_2432_3_256 } from "@/scripts/utils/types";

const REGISTRATION_PROXY = "0x6BF01a93ED6134681BDDd63933867F982895ca8c";

export = async (deployer: Deployer) => {
  const [signer] = await ethers.getSigners();
  const registration = Registration2Mock__factory.connect(REGISTRATION_PROXY, signer);

  // Upgrade Registration2Mock to add mockRemovePassportVerifier
  const registrationImpl = await deployer.deploy(Registration2Mock__factory);
  await registration.upgradeToAndCall(await registrationImpl.getAddress(), "0x");
  console.log("Registration2Mock upgraded to:", await registrationImpl.getAddress());

  // Deploy new verifier
  const verifier = await deployer.deploy(NoirRegisterIdentity_2_256_3_6_576_248_1_2432_3_256__factory);
  const verifierAddr = await verifier.getAddress();

  // Replace verifier
  await registration.mockRemovePassportVerifier(Z_NOIR_PASSPORT_2_256_3_6_576_248_1_2432_3_256);
  await registration.mockAddPassportVerifier(Z_NOIR_PASSPORT_2_256_3_6_576_248_1_2432_3_256, verifierAddr);

  console.log("NoirRegisterIdentity_2_256_3_6_576_248_1_2432_3_256 redeployed to:", verifierAddr);
};
