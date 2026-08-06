use typesec_integrations::receipt::CognitionCommitReceipt;

fn main() {
    let receipt: CognitionCommitReceipt = todo!();
    let _forged = CognitionCommitReceipt {
        schema_version: 3,
        ..receipt
    };
}
