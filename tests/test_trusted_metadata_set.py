import copy
import json
import logging
import os
import sys
import unittest
from typing import Dict, Any
from datetime import datetime

from tuf import exceptions
from tuf.api.metadata import Metadata, MetaFile
from tuf.ngclient._internal.trusted_metadata_set import(
    TrustedMetadataSet,
    verify_with_threshold
)
from securesystemslib import hash as sslib_hash
from securesystemslib.signer import SSlibSigner
from securesystemslib.interface import import_ed25519_privatekey_from_file

from tests import utils

logger = logging.getLogger(__name__)

class TestTrustedMetadataSet(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.repo_dir = os.path.join(
            os.getcwd(), 'repository_data', 'repository', 'metadata'
        )
        cls.metadata = {}
        for md in ["root", "timestamp", "snapshot", "targets", "role1", "role2"]:
            with open(os.path.join(cls.repo_dir, f"{md}.json"), "rb") as f:
                cls.metadata[md] = f.read()

        keystore_dir = os.path.join(os.getcwd(), 'repository_data', 'keystore')
        cls.keystore = {}
        for role in ['delegation', 'snapshot', 'targets', 'timestamp']:
            cls.keystore[role] = import_ed25519_privatekey_from_file(
                os.path.join(keystore_dir, role + '_key'),
                password="password"
            )

    def setUp(self) -> None:
        self.trusted_set = TrustedMetadataSet(self.metadata["root"])

    def test_update(self):
        self.trusted_set.root_update_finished()
        self.trusted_set.update_timestamp(self.metadata["timestamp"])
        self.trusted_set.update_snapshot(self.metadata["snapshot"])
        self.trusted_set.update_targets(self.metadata["targets"])
        self.trusted_set.update_delegated_targets(
            self.metadata["role1"], "role1", "targets"
        )
        self.trusted_set.update_delegated_targets(
            self.metadata["role2"], "role2", "role1"
        )
        # the 4 top level metadata objects + 2 additional delegated targets
        self.assertTrue(len(self.trusted_set), 6)

    def test_out_of_order_ops(self):
        # Update timestamp before root is finished
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_timestamp(self.metadata["timestamp"])

        self.trusted_set.root_update_finished()
        with self.assertRaises(RuntimeError):
            self.trusted_set.root_update_finished()

        # Update snapshot before timestamp
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_snapshot(self.metadata["snapshot"])

        self.trusted_set.update_timestamp(self.metadata["timestamp"])

        # Update targets before snapshot
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_targets(self.metadata["targets"])

        self.trusted_set.update_snapshot(self.metadata["snapshot"])

        # update timestamp after snapshot
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_timestamp(self.metadata["timestamp"])

        # Update delegated targets before targets
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_delegated_targets(
                self.metadata["role1"], "role1", "targets"
            )

        self.trusted_set.update_targets(self.metadata["targets"])
        self.trusted_set.update_delegated_targets(
            self.metadata["role1"], "role1", "targets"
        )

        self.trusted_set.update_targets(self.metadata["targets"])
        self.trusted_set.update_delegated_targets(
            self.metadata["role1"], "role1", "targets"
        )

    def test_update_with_invalid_json(self):
        # root.json not a json file at all
        with self.assertRaises(exceptions.RepositoryError):
            TrustedMetadataSet(b"")
        # root.json is invalid
        root = Metadata.from_bytes(self.metadata["root"])
        root.signed.version += 1
        with self.assertRaises(exceptions.RepositoryError):
            TrustedMetadataSet(json.dumps(root.to_dict()).encode())

        self.trusted_set.root_update_finished()

        top_level_md = [
            (self.metadata["timestamp"], self.trusted_set.update_timestamp),
            (self.metadata["snapshot"], self.trusted_set.update_snapshot),
            (self.metadata["targets"], self.trusted_set.update_targets),
        ]
        for metadata, update_func in top_level_md:
            # metadata is not json
            with self.assertRaises(exceptions.RepositoryError):
                update_func(b"")
            # metadata is invalid
            md = Metadata.from_bytes(metadata)
            md.signed.version += 1
            with self.assertRaises(exceptions.RepositoryError):
                update_func(json.dumps(md.to_dict()).encode())

            # metadata is of wrong type
            with self.assertRaises(exceptions.RepositoryError):
                update_func(self.metadata["root"])

            update_func(metadata)


    def test_verify_with_threshold_wrong_delegator(self):
        delegated_role = Metadata.from_bytes(self.metadata["role1"])
        timestamp = Metadata.from_bytes(self.metadata["timestamp"])
        with self.assertRaises(ValueError):
            verify_with_threshold(timestamp, "role1", delegated_role)

    def test_verify_with_threshold_non_existent_role_name(self):
        delegated_role = Metadata.from_bytes(self.metadata["role1"])
        targets = Metadata.from_bytes(self.metadata["targets"])
        with self.assertRaises(ValueError):
            verify_with_threshold(targets, "foo", delegated_role)

    def test_update_root_invalid_type(self):
        # new_root data with invalid snapshot type
        invalid_type_data = json.loads(self.metadata["root"])
        invalid_type_data["signed"]["_type"] = "snapshot"
        invalid_type_data["signed"]["meta"] = {"file1.txt": {"version": 1}}
        invalid_type_data = json.dumps(invalid_type_data).encode()
        # RepositoryError is thrown during new_root deserialization.
        # It's not thrown when checking new_root.signed.type != "root"
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_root(invalid_type_data)

    def test_update_root_new_root_cannot_be_verified_with_threshold(self):
        # new_root data with threshold which cannot be verified.
        modified_threshold_data = copy.deepcopy(
            json.loads(self.metadata["root"])
        )
        modified_threshold_data["signed"]["roles"]["root"]["threshold"] = 2
        modified_threshold_data = json.dumps(modified_threshold_data).encode()
        with self.assertRaises(exceptions.UnsignedMetadataError):
            self.trusted_set.update_root(modified_threshold_data)

    def test_update_root_new_root_ver_same_as_trusted_root_ver(self):
        with self.assertRaises(exceptions.ReplayedMetadataError):
            self.trusted_set.update_root(self.metadata["root"])

    def test_update_root_after_successful_root_update(self):
        # if _root_update_finished, then fail when calling update_root
        self.trusted_set.root_update_finished()
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_root(self.metadata["root"])
        self.trusted_set._root_update_finished = False

    def test_root_update_finished_expired(self):
        # call root_update_finished when trusted root has expired
        expired_datetime = datetime.strptime(
            "1970-01-01T00:00:00Z", "%Y-%m-%dT%H:%M:%SZ"
        )
        self.trusted_set.root.signed.expires = expired_datetime
        with self.assertRaises(exceptions.ExpiredMetadataError):
            self.trusted_set.root_update_finished()

    def _sign_modified_obj(
        self,
        role:str,
        metadata_obj: Metadata
    ) -> Dict[str, Any]:
        key_dict = self.keystore[role]
        sslib_signer = SSlibSigner(key_dict)
        signature = metadata_obj.sign(sslib_signer)
        return signature.to_dict()


    def _setup_update_snapshot_or_timestamp_test(self):
        self.trusted_set.root_update_finished()
        self.trusted_set.update_timestamp(self.metadata["timestamp"])

    def test_update_timestamp_new_timestamp_ver_below_trusted_ver(self):
        self._setup_update_snapshot_or_timestamp_test()
        # new_timestamp.version < trusted_timestamp.version
        self.trusted_set.timestamp.signed.version = 2
        with self.assertRaises(exceptions.ReplayedMetadataError):
            self.trusted_set.update_timestamp(self.metadata["timestamp"])

    def test_update_timestamp_snapshot_ver_below_trusted_snapshot_ver(self):
        self._setup_update_snapshot_or_timestamp_test()
        # new_timestamp.snapshot.version < trusted_timestamp.snapshot.version
        self.trusted_set.timestamp.signed.meta["snapshot.json"].version = 2
        with self.assertRaises(exceptions.ReplayedMetadataError):
            self.trusted_set.update_timestamp(self.metadata["timestamp"])

    def test_update_timestamp_snapshot_ver_below_trusted_snapshot_ver(self):
        self._setup_update_snapshot_or_timestamp_test()
        # new_timestamp has expired
        timestamp = Metadata.from_bytes(self.metadata["timestamp"])
        timestamp.signed.expires = datetime.strptime(
            "1970-01-01T00:00:00Z", "%Y-%m-%dT%H:%M:%SZ"
        )
        self._sign_modified_obj("timestamp", timestamp)
        new_timestamp_byte_data = json.dumps(timestamp.to_dict()).encode()
        with self.assertRaises(exceptions.ExpiredMetadataError):
            self.trusted_set.update_timestamp(new_timestamp_byte_data)


    def _calculate_modified_hashes(
        self, true_hashes,
        data: bytes
    ) -> Dict[str, str]:
        modified_hashes = {}
        # Calculate hashes on modified data in order to pass hashes verification.
        for algo in true_hashes.keys():
            digest_object = sslib_hash.digest(algo)
            digest_object.update(data)
            observed_hash = digest_object.hexdigest()
            modified_hashes[algo] = observed_hash
        return modified_hashes

    def test_update_snapshot_new_snapshot_invalid_type(self):
        self._setup_update_snapshot_or_timestamp_test()
        # new_snapshot data with invalid targets type
        invalid_type_data = json.loads(self.metadata["snapshot"])
        invalid_type_data["signed"]["_type"] = "targets"
        invalid_type_data["signed"]["targets"] = {}
        invalid_type_data = json.dumps(invalid_type_data).encode()
        timestamp_meta = self.trusted_set.timestamp.signed.meta["snapshot.json"]
        true_hashes = timestamp_meta.hashes or {}
        modified_hashes = self._calculate_modified_hashes(
            true_hashes, invalid_type_data
        )
        self.trusted_set.timestamp.signed.meta["snapshot.json"].hashes = modified_hashes

        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_snapshot(invalid_type_data)

    def test_update_snapshot_after_targets_updated(self):
        self._setup_update_snapshot_or_timestamp_test()
        # cannot update snapshot after targets update completes or targets != None
        targets_obj = Metadata.from_bytes(self.metadata["targets"])
        self.trusted_set._trusted_set["targets"] = targets_obj
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_snapshot(self.metadata["snapshot"])

    def test_update_snapshot_with_invalid_json(self):
        self._setup_update_snapshot_or_timestamp_test()
        #  Deserialization error - failed to decode the new_snapshot JSON.
        timestamp_meta = self.trusted_set.timestamp.signed.meta["snapshot.json"]
        true_hashes = timestamp_meta.hashes or {}

        modified_hashes = self._calculate_modified_hashes(
            true_hashes, b'{""sig": }'
        )
        self.trusted_set.timestamp.signed.meta["snapshot.json"].hashes = modified_hashes
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_snapshot(b'{""sig": }')
        self.trusted_set.timestamp.signed.meta["snapshot.json"].hashes = true_hashes

    def test_update_snapshot_cannot_verify_snapshot_with_threshold(self):
        self._setup_update_snapshot_or_timestamp_test()
        # root data with threshold which cannot be verified for new_snapshot
        self.trusted_set.root.signed.roles["snapshot"].threshold = 2
        with self.assertRaises(exceptions.UnsignedMetadataError):
            self.trusted_set.update_snapshot(self.metadata["snapshot"])
        self.trusted_set.root.signed.roles["snapshot"].threshold = 1

    def test_update_snapshot_version_different_timestamp_snapshot_version(self):
        self._setup_update_snapshot_or_timestamp_test()
        # new_snapshot.version != trusted timestamp.meta["snapshot"].version
        self.trusted_set.timestamp.signed.meta["snapshot.json"].version = 2
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_snapshot(self.metadata["snapshot"])
        self.trusted_set.timestamp.signed.meta["snapshot.json"].version = 1


    def _setup_update_snapshot_after_successful_update_test(self):
        self._setup_update_snapshot_or_timestamp_test()
        self.trusted_set.update_snapshot(self.metadata["snapshot"])

    def test_update_snapshot_after_successful_update_new_snapshot_no_meta(self):
        self._setup_update_snapshot_after_successful_update_test()
        # Test removing a meta_file in new_snapshot compared to the old snapshot
        snapshot_obj = Metadata.from_bytes(self.metadata["snapshot"])
        snapshot_obj.signed.meta = {}
        # prepare timestamp.meta["snapshot"].hashes
        self._sign_modified_obj("snapshot", snapshot_obj)
        timestamp_meta = self.trusted_set.timestamp.signed.meta["snapshot.json"]
        true_hashes = timestamp_meta.hashes or {}
        modified_snapshot_data = json.dumps(snapshot_obj.to_dict()).encode()
        modified_hashes = self._calculate_modified_hashes(
            true_hashes, modified_snapshot_data
        )
        self.trusted_set.timestamp.signed.meta["snapshot.json"].hashes = modified_hashes

        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_snapshot(modified_snapshot_data)

    def test_update_snapshot_after_succesfull_update_new_snapshot_meta_version_different(self):
        self._setup_update_snapshot_after_successful_update_test()
        # snapshot.meta["project1"].version != new_snapshot.meta["project1"].version
        for meta_file_path in self.trusted_set.snapshot.signed.meta.keys():
            self.trusted_set.snapshot.signed.meta[meta_file_path].version = 2
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_snapshot(self.metadata["snapshot"])

    def test_update_snapshot_after_succesfull_expired_new_snapshot(self):
        self._setup_update_snapshot_after_successful_update_test()
        # new_snapshot has expired
        snapshot_obj = Metadata.from_bytes(self.metadata["snapshot"])
        snapshot_obj.signed.expires = datetime.strptime(
            "1970-01-01T00:00:00Z", "%Y-%m-%dT%H:%M:%SZ"
        )
        self._sign_modified_obj("snapshot", snapshot_obj)
        modified_snapshot_data = json.dumps(snapshot_obj.to_dict()).encode()
        timestamp_meta = self.trusted_set.timestamp.signed.meta["snapshot.json"]
        true_hashes = timestamp_meta.hashes or {}
        modified_hashes = self._calculate_modified_hashes(
            true_hashes, modified_snapshot_data
        )
        self.trusted_set.timestamp.signed.meta["snapshot.json"].hashes = modified_hashes
        # remove length so it doesn't intervene the validation.
        self.trusted_set.timestamp.signed.meta["snapshot.json"].length = None
        with self.assertRaises(exceptions.ExpiredMetadataError):
            self.trusted_set.update_snapshot(modified_snapshot_data)


    def setup_update_targets_test(self):
        self.trusted_set.root_update_finished()
        self.trusted_set.update_timestamp(self.metadata["timestamp"])
        self.trusted_set.update_snapshot(self.metadata["snapshot"])

    def test_update_targets_no_meta_in_snapshot(self):
        self.setup_update_targets_test()
        # remove meta information with information about targets from snapshot
        self.trusted_set.snapshot.signed.meta = {}
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_targets(self.metadata["targets"])

    def test_update_targets_hash_different_than_snapshot_meta_hash(self):
        self.setup_update_targets_test()
        # observed_hash != stored hash in snapshot meta for targets
        true_hashes = {}
        for target_path, meta_file in self.trusted_set.snapshot.signed.meta.items():
            true_hashes[target_path] = meta_file.hashes
            self.trusted_set.snapshot.signed.meta[target_path].hashes = {"sha256": "b"}
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_targets(self.metadata["targets"])

    def test_update_targets_version_different_snapshot_meta_version(self):
        self.setup_update_targets_test()
        # new_delegate.signed.version != meta.version stored in snapshot
        for target_path in self.trusted_set.snapshot.signed.meta.keys():
            self.trusted_set.snapshot.signed.meta[target_path].version = 2
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_targets(self.metadata["targets"])

    def test_update_targets_expired_new_target(self):
        self.setup_update_targets_test()
        # new_delegated_target has expired
        targets_obj = Metadata.from_bytes(self.metadata["targets"])
        targets_obj.signed.expires = datetime.strptime(
            "1970-01-01T00:00:00Z", "%Y-%m-%dT%H:%M:%SZ"
        )
        self._sign_modified_obj("targets", targets_obj)
        modified_targets_data = json.dumps(targets_obj.to_dict()).encode()
        with self.assertRaises(exceptions.ExpiredMetadataError):
            self.trusted_set.update_targets(modified_targets_data)

    # TODO test updating over initial metadata (new keys, newer timestamp, etc)


if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
