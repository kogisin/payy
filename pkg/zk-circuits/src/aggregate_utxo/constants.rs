use expect_test::Expect;
use halo2_base::halo2_proofs::{halo2curves::bn256::G1Affine, plonk::VerifyingKey};
use once_cell::sync::Lazy;

use super::AggregateUtxo;

const GENERATED_UTXO_AGGREGATE_3_161_12_VK: Expect = expect_test::expect![[r#"
    "00000015000000187cdf4bdb7d3f837997a3279f7c37a94ad41e48cc4676de78ef164c4d53e57ea8741d9d613f77c292e8d1db3612d4deda12f5cd4c9bc5baaefd28fe16474c1e92107d17ed4de445c1a6cce6cdead4855348027b7822bb7ae2822ab4e0d8c3ed87f9d64c47561a18a1428d2f3d3822561fb281c06accb9a6a8b1320f7ced0932a7c5df5cc2b49149b5460af5a170d5023c0dbc85d2c28f39ff377ad66199305a8bf0a0a56085773d2f49a8b76ede5311934352de22833a3f2f8a6f069cd58dff1d02ae920386c882283c466ead3a9e8ba724f6e409b36e9bd0aa6b49497ffdbf9efba688991c9272fd1f76109e34311b4b2094987a32bf45217fd0f4a63ceea7980967a769f962ef9ba9d3a7afbe7ced5bd7668271b72250e97f0a6dc7babf40174cfeaccd7269609a8fd1b1a68ed1796d239d4a2c9654a8fc5db7e1ffc5b46416fb8db527ada9ddeb42cebaa9a0183440e4123bf7cb04892fa678f4d43e5aad88736b8906cf0d2624c97ef62fe1c63b803bf9ddf2840aced1f8f6f2fde3be1e9af0b6daf1e493f5d2fd047078dc5315b5520fcdc4b85272eb0d24e69d9c127f87b6837fd192a049e365c0d8accda539e2b3feaeafda65f28fb22a0efefd74b306bc6bb2a9979c85cf9855a9410778606b1af0d9c0d33578ca32994f6692883c873be96da8d37aa1a690fc8add9670be302d546943c0c269895dca0ff7d9411c0c8546fd9db1bb06d05449e991edf31461eda065e2ddcefac6c3393665966daf839e3dd52f78458fa11e5f7c93b52b2ee755b425d142b6ebed0695146c5c62c5afe4bbef572e329be8f9fb617665034b3ffb91db659a55fb2da5fff3e07410aa95a2b85ac92820fa779ea806647fc6ed975140082a42c8c921f285d842396f3d2be165069dc095be52f5f97e2939b2f5bf63b39684b0262d6dd0ec754d67a4459bc9a07a5f4e9cd11bcfe74d2d9f744b7ea615cf474e13b8e610706b597645f02830f715bdb63d53388d8d52d387a5a7c1157ba89e422c71772faa28f4ca2c4c1ac745fb9a91da64307bd5c6480233c5e388889bc0419f0108981b187f8ac27616fb2e8b794aa4df3bc42db788f16f926c1640768d1c613add04a0782e3b38c72fa7cdda8fd4d45cdbfc990f2cb7bf914eb12f434e6d6d083708ae24fbe49f15891443a300d21049096ed632e8608cff3845f2d859d2489dfa7d094717239d7b29ff832e069eda678eaebb5d878d30d29d2f9359d727cf8f9d1b2bf9664d552d08743930a6ca3a5ed164d71edb32d34b200957db585751ef5a30561ea5ced19a8952d27dc648a4cca22909629b762deb4b03078e0b5290e6fe9c80ec28f803432c8a130728a45ce437e1d65a9742efa9f6790cccbe16471cf24412837432545225e73f62dc877860fd8edd565dfcb813316bdad1997263eadd560a0da674d07ea46fe0715ac561158b29680682c00e3dbfe61070a0afc3d9ce81e8cd61bb635c2cafbbd577c119bc1b37987d81c69236084cbee68140feed04e112c07073c4819eaa98594eef61408009a95f1b86164eda3cf4b7c8196d4986046d648b5fc9d805a8aadab654623de3380cf550c3e6128eb95cca9060d3cb784a83d342bbe0981dda7328db8c1c5328fe5c39b507e9e98e20c4148a339bad639aa69629afe36d99faa494b87f778e5ec93b9fc9468f900765ee5e60da6e43141d1809fb4d7761814efa88675b4b8875894ed9d1bbd315970ca3e45d6686bbadc3d5c91424e44104fa04fe1fa61d5ebd353931eb7fe4e1ff714eb7f4c425c83ef4ac50a353580e9b602852bbbe700c4c2414081b80cf2614b6133f22f52ebd29ec1ac3ddd2ff5f98e3a319d6aa24343861fec09f10a1bfcdc0507241db47a95202d583c490100088d7f3d4d088e09c765a93fdbfcf7872fc6df899565fe887c4781a6a322b353020624067df92e16ec47c14863662fb2a059232a14a8bba63b1d6fc9fcea9a3ada1"
"#]];

pub static UTXO_AGGREGATE_3_161_12_VK: Lazy<VerifyingKey<G1Affine>> = Lazy::new(|| {
    #[allow(clippy::unwrap_used)]
    let vk_bytes = hex::decode(
        GENERATED_UTXO_AGGREGATE_3_161_12_VK
            .data()
            .replace(['\n', '"', ' '], ""),
    )
    .unwrap();
    #[allow(clippy::unwrap_used)]
    VerifyingKey::<G1Affine>::from_bytes::<AggregateUtxo<3, 161, 12>>(
        &vk_bytes,
        halo2_base::halo2_proofs::SerdeFormat::Processed,
    )
    .unwrap()
});

#[cfg(test)]
mod tests {
    use crate::{aggregate_utxo::AggregateUtxo, data::ParameterSet};

    use super::*;

    #[test]
    #[ignore]
    fn generate_utxo_aggregate_vk() {
        let aggregate_utxo = AggregateUtxo::<3, 161, 12>::default();

        let params = ParameterSet::TwentyOne;
        let (_, vk) = aggregate_utxo.keygen(params);

        let generated_vk =
            hex::encode(vk.to_bytes(halo2_base::halo2_proofs::SerdeFormat::Processed));
        GENERATED_UTXO_AGGREGATE_3_161_12_VK.assert_debug_eq(&generated_vk);
    }
}
