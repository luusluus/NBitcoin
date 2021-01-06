using NBitcoin.Altcoins.HashX11;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using System;
using System.Linq;

namespace NBitcoin.Altcoins
{
	public class Blocknet : NetworkSetBase
	{
		public static Blocknet Instance { get; } = new Blocknet();
		public override string CryptoCode => "BLOCK";
		private Blocknet()
		{

		}

		public class BlocknetConsensusFactory : ConsensusFactory
		{
			private BlocknetConsensusFactory()
			{
			}

			public static BlocknetConsensusFactory Instance { get; } = new BlocknetConsensusFactory();

			public override BlockHeader CreateBlockHeader()
			{
				return new BlocknetBlockHeader();
			}
			public override Block CreateBlock()
			{
				return new BlocknetBlock(new BlocknetBlockHeader());
			}
		}

#pragma warning disable CS0618 // Type or member is obsolete
		public class BlocknetBlockHeader : BlockHeader
		{
			// https://github.com/blocknetdx/blocknet/blob/master/src/primitives/block.cpp
			private static byte[] CalculateHash(byte[] data, int offset, int count)
			{
				return new Quark().ComputeBytes(data.Skip(offset).Take(count).ToArray());
			}

			protected override HashStreamBase CreateHashStream()
			{
				return BufferedHashStream.CreateFrom(CalculateHash);
			}
		}

		public class BlocknetBlock : Block
		{
			public BlocknetBlock(BlocknetBlockHeader header) : base(header)
			{

			}
			public override ConsensusFactory GetConsensusFactory()
			{
				return BlocknetConsensusFactory.Instance;
			}
		}

		protected override void PostInit()
		{
			RegisterDefaultCookiePath("Blocknet", new FolderName() { TestnetFolder = "testnet5" });
		}

		protected override NetworkBuilder CreateMainnet()
		{
			// https://github.com/blocknetdx/blocknet/blob/4cafcea7c61c44f975982913a1925463435a12d2/src/chainparams.cpp
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 210000,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				BIP34Hash = new uint256(),
				PowLimit = new Target(new uint256("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				MinimumChainWork = new uint256("00000000000000000000000000000000000000000000000563b4a73316dfc193"),
				PowTargetTimespan = TimeSpan.FromSeconds(60),
				PowTargetSpacing = TimeSpan.FromSeconds(60),
				PowAllowMinDifficultyBlocks = false,
				CoinbaseMaturity = 100,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 45,
				MinerConfirmationWindow = 60,
				ConsensusFactory = BlocknetConsensusFactory.Instance,
				SupportSegwit = true
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 139 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 19 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x3A, 0x80, 0x61, 0xA0 })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x3A, 0x80, 0x58, 0x37 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("block"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("block"))
			.SetMagic(0xA3A2A0A1)
			.SetPort(41412)
			.SetRPCPort(41414)
			// https://github.com/luusluus/blocknet/blob/master/src/version.h
			.SetMaxP2PVersion(70713)
			.SetName("blocknet-main")
			.AddAlias("blocknet-mainnet")
			.AddDNSSeeds(new[]
			{
				new DNSSeedData("seed1.blocknet.co", "seed1.blocknet.co"),
				new DNSSeedData("seed2.blocknet.co", "seed2.blocknet.co"),
				new DNSSeedData("seed3.blocknet.co", "seed3.blocknet.co"),
			})
			.AddSeeds(new NetworkAddress[0])
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000f26bb5a8606ca026d9c17f12b6e215812bbe33ab19073ac2f45af56d3fe9f0b1b9f78959ffff0f1ef7360b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3d04ffff001d010435646563656e7472616c697a656420636f6e73656e7375732062617365642064656d6f63726163792069732074686520667574757265ffffffff0100ba1dd20500000043410452c91a00518fb8c6d38100341f88499554284d1ba75097cc25ae5a0d811835c63d2cb46c8855304bca81c452b63ce71fcb6897d06f8000450841f72602457f74ac00000000");
			return builder;
		}

		protected override NetworkBuilder CreateTestnet()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 210000,
				MajorityEnforceBlockUpgrade = 51,
				MajorityRejectBlockOutdated = 75,
				MajorityWindow = 100,
				BIP34Hash = new uint256(),
				PowLimit = new Target(new uint256("0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				MinimumChainWork = new uint256("0000000000000000000000000000000000000000000000008da8d3d2e63fb960"),
				PowTargetTimespan = TimeSpan.FromSeconds(60),
				PowTargetSpacing = TimeSpan.FromSeconds(60),
				PowAllowMinDifficultyBlocks = true,
				CoinbaseMaturity = 15,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 45,
				MinerConfirmationWindow = 60,
				ConsensusFactory = BlocknetConsensusFactory.Instance,
				SupportSegwit = true
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 139 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 19 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x3A, 0x80, 0x61, 0xA0 })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x3A, 0x80, 0x58, 0x37 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("tblock"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("tblock"))
			.SetMagic(0xBA657645)
			.SetPort(41474)
			.SetRPCPort(41419)
			.SetMaxP2PVersion(70713)
		   .SetName("blocknet-test")
		   .AddAlias("blocknet-testnet")
		   .AddDNSSeeds(new[]
		   {
				new DNSSeedData("3.16.3.126", "3.16.3.126"),
				new DNSSeedData("18.224.130.185", "18.224.130.185"),
				new DNSSeedData("18.213.44.27", "18.213.44.27"),
				new DNSSeedData("34.196.102.239", "34.196.102.239")
		   })
		   .AddSeeds(new NetworkAddress[0])
		   .SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000f26bb5a8606ca026d9c17f12b6e215812bbe33ab19073ac2f45af56d3fe9f0b16be2445cffff3f2002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3d04ffff001d010435646563656e7472616c697a656420636f6e73656e7375732062617365642064656d6f63726163792069732074686520667574757265ffffffff0100ba1dd20500000043410452c91a00518fb8c6d38100341f88499554284d1ba75097cc25ae5a0d811835c63d2cb46c8855304bca81c452b63ce71fcb6897d06f8000450841f72602457f74ac00000000");
			return builder;
		}

		protected override NetworkBuilder CreateRegtest()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 150,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				BIP34Hash = new uint256(),
				PowLimit = new Target(new uint256("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				MinimumChainWork = uint256.Zero,
				PowTargetTimespan = TimeSpan.FromSeconds(60),
				PowTargetSpacing = TimeSpan.FromSeconds(60),
				PowAllowMinDifficultyBlocks = true,
				CoinbaseMaturity = 50,
				PowNoRetargeting = true,
				RuleChangeActivationThreshold = 108,
				MinerConfirmationWindow = 144,
				ConsensusFactory = BlocknetConsensusFactory.Instance,
				SupportSegwit = true,
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 139 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 19 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x3A, 0x80, 0x61, 0xA0 })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x3A, 0x80, 0x58, 0x37 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("blockrt"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("blockrt"))
			.SetMagic(0xAC7ECFA1)
			.SetPort(41489)
			.SetRPCPort(41499)
			.SetMaxP2PVersion(70713)
			.SetName("block-reg")
			.AddAlias("block-regtest")
			.AddAlias("blocknet-reg")
			.AddAlias("blocknet-regtest")
			.AddDNSSeeds(new DNSSeedData[0])
			.AddSeeds(new NetworkAddress[0])
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000b28c4f1d46cf52862d124c6e59dc53145546a42f8645ec6ff62c623bd25ed723bb2eac56ffff7f2002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3d04ffff001d010435646563656e7472616c697a656420636f6e73656e7375732062617365642064656d6f63726163792069732074686520667574757265ffffffff0100f2052a0100000043410452c91a00518fb8c6d38100341f88499554284d1ba75097cc25ae5a0d811835c63d2cb46c8855304bca81c452b63ce71fcb6897d06f8000450841f72602457f74ac00000000");
			return builder;
		}
	}
}
