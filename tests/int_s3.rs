use anyhow::Result;
use kingfisher::s3::visit_bucket_objects;

#[tokio::test]
async fn test_visit_public_bucket() -> Result<()> {
    let mut objects = Vec::new();
    visit_bucket_objects("wikisum", None, None, None, |key, data| {
        objects.push((key, data));
        Ok(())
    })
    .await?;

    assert!(objects.iter().any(|(k, _)| k == "README.txt"), "README object not found");
    let creds = objects.iter().find(|(k, _)| k == "README.txt").expect("README object");
    let body = std::str::from_utf8(&creds.1)?;
    assert!(
        body.contains("This dataset provides how-to articles"),
        "expected README file"
    );
    Ok(())
}