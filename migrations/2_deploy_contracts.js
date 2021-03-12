const Ownable = artifacts.require("Ownable");
const CA = artifacts.require("CA");

module.exports = function(deployer) {
  deployer.deploy(Ownable);
  deployer.link(Ownable, CA);
  deployer.deploy(CA);
};
