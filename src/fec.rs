use anyhow::{Result, bail};
use reed_solomon_erasure::galois_8::ReedSolomon;

/// 使用 Reed-Solomon 对固定大小数据分片生成冗余分片。
pub fn encode_block(data: &[Vec<u8>], parity_count: usize) -> Result<Vec<Vec<u8>>> {
    // step.1 校验数据分片并构建编码器
    if data.is_empty() || parity_count == 0 {
        bail!("数据分片和冗余分片数量必须大于零")
    }
    let shard_size = data[0].len();
    if shard_size == 0 || data.iter().any(|shard| shard.len() != shard_size) {
        bail!("所有数据分片必须具有相同的非零长度")
    }
    let codec = ReedSolomon::new(data.len(), parity_count)?;
    // step.2 复制数据分片并计算纠删码冗余
    let mut shards = data.iter().cloned().map(Some).collect::<Vec<_>>();
    shards.extend((0..parity_count).map(|_| Some(vec![0; shard_size])));
    let mut owned = shards.into_iter().map(Option::unwrap).collect::<Vec<_>>();
    codec.encode(&mut owned)?;
    Ok(owned.split_off(data.len()))
}

/// 从含丢失项的分片集合恢复原始数据分片。
pub fn recover_block(
    shards: &mut [Option<Vec<u8>>],
    data_count: usize,
    parity_count: usize,
) -> Result<Vec<Vec<u8>>> {
    // step.1 校验分片布局并创建对应编码器
    if data_count == 0 || parity_count == 0 || shards.len() != data_count + parity_count {
        bail!("分片数量与数据、冗余配置不一致")
    }
    if shards.iter().flatten().any(|shard| shard.is_empty()) {
        bail!("收到的分片不能是空数据")
    }
    let codec = ReedSolomon::new(data_count, parity_count)?;
    // step.2 校验可恢复性并重建缺失数据
    codec.reconstruct(shards)?;
    Ok(shards[..data_count]
        .iter()
        .map(|shard| shard.clone().expect("重建后数据分片必须存在"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{encode_block, recover_block};

    /// 验证短突发丢失不超过冗余数时可以精确恢复数据。
    #[test]
    fn recovers_random_and_burst_erasures() {
        // step.1 构建固定大小数据块及两片冗余
        let original = (0..8)
            .map(|index| vec![index as u8; 1100])
            .collect::<Vec<_>>();
        let parity = encode_block(&original, 2).unwrap();
        let encoded = original
            .iter()
            .cloned()
            .chain(parity)
            .map(Some)
            .collect::<Vec<_>>();
        // step.2 覆盖单点随机丢失和长度二的连续突发
        for losses in [vec![1], vec![0, 2], vec![6, 7]] {
            let mut sample = encoded.clone();
            for index in losses {
                sample[index] = None;
            }
            assert_eq!(recover_block(&mut sample, 8, 2).unwrap(), original);
        }
    }

    /// 验证丢失分片超过冗余数时明确报告不可恢复。
    #[test]
    fn rejects_more_losses_than_parity() {
        // step.1 生成包含两片冗余的测试块
        let original = (0..8).map(|value| vec![value; 256]).collect::<Vec<_>>();
        let parity = encode_block(&original, 2).unwrap();
        let mut sample = original
            .into_iter()
            .chain(parity)
            .map(Some)
            .collect::<Vec<_>>();
        // step.2 人为丢失三片并确认恢复失败
        sample[0] = None;
        sample[1] = None;
        sample[2] = None;
        assert!(recover_block(&mut sample, 8, 2).is_err());
    }
}
