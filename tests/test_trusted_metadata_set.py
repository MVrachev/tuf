import copy
import json
import logging
import os
import sys
import unittest
from typing import Dict, Any
from datetime import datetime

from tuf import exceptions
from tuf.api.metadata import Metadata
from tuf.ngclient._internal.trusted_metadata_set import(
    TrustedMetadataSet
)
from securesystemslib.signer import SSlibSigner
from securesystemslib.interface import(
    import_ed25519_privatekey_from_file,
    import_rsa_privatekey_from_file
)

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
        root_key_dict = import_rsa_privatekey_from_file(
            os.path.join(keystore_dir, "root" + '_key'),
            password="password"
        )
        cls.keystore["root"] = SSlibSigner(root_key_dict)
        for role in ["delegation", "snapshot", "targets", "timestamp"]:
            key_dict = import_ed25519_privatekey_from_file(
                os.path.join(keystore_dir, role + '_key'),
                password="password"
            )
            cls.keystore[role] = SSlibSigner(key_dict)

    def setUp(self) -> None:
        self.trusted_set = TrustedMetadataSet(self.metadata["root"])

    def _root_update_finished_and_update_timestamp(self):
        self.trusted_set.root_update_finished()
        self.trusted_set.update_timestamp(self.metadata["timestamp"])

    def _update_all_besides_targets(self):
        self.trusted_set.root_update_finished()
        self.trusted_set.update_timestamp(self.metadata["timestamp"])
        self.trusted_set.update_snapshot(self.metadata["snapshot"])

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

        # Update root after a previous successful root update
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_root(self.metadata["root"])

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

        # Update snapshot after sucessful targets update
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_snapshot(self.metadata["snapshot"])

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

        # update_root called with the wrong metadata type
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_root(self.metadata["snapshot"])

        self.trusted_set.root_update_finished()

        top_level_md = [
            (self.metadata["timestamp"], self.trusted_set.update_timestamp),
            (self.metadata["snapshot"], self.trusted_set.update_snapshot),
            (self.metadata["targets"], self.trusted_set.update_targets),
        ]
        for metadata, update_func in top_level_md:
            md = Metadata.from_bytes(metadata)
            if md.signed.type == "snapshot":
                # timestamp hashes and length intervene when testing snapshot
                self.trusted_set.timestamp.signed.meta["snapshot.json"].hashes = None
                self.trusted_set.timestamp.signed.meta["snapshot.json"].length = None
            # metadata is not json
            with self.assertRaises(exceptions.RepositoryError):
                update_func(b"")
            # metadata is invalid
            md.signed.version += 1
            with self.assertRaises(exceptions.RepositoryError):
                update_func(json.dumps(md.to_dict()).encode())

            # metadata is of wrong type
            with self.assertRaises(exceptions.RepositoryError):
                update_func(self.metadata["root"])

            update_func(metadata)


    def test_update_root_new_root_cannot_be_verified_with_threshold(self):
        # new_root data with threshold which cannot be verified.
        modified_threshold_data = copy.deepcopy(
            json.loads(self.metadata["root"])
        )
        # change something in root so signature doesn't match the content.
        modified_threshold_data["signed"]["roles"]["root"]["version"] = 2
        modified_threshold_data = json.dumps(modified_threshold_data).encode()
        with self.assertRaises(exceptions.UnsignedMetadataError):
            self.trusted_set.update_root(modified_threshold_data)

    def test_update_root_new_root_ver_same_as_trusted_root_ver(self):
        with self.assertRaises(exceptions.ReplayedMetadataError):
            self.trusted_set.update_root(self.metadata["root"])

    def _sign_modified_obj(
        self,
        role:str,
        metadata_obj: Metadata
    ) -> Dict[str, Any]:
        sslib_signer = self.keystore[role]
        signature = metadata_obj.sign(sslib_signer)
        return signature.to_dict()

    def test_root_update_finished_expired(self):
        root_obj = Metadata.from_bytes(self.metadata["root"])
        root_obj.signed.expires = datetime(1970, 1, 1)
        self._sign_modified_obj("root", root_obj)
        modified_root_data = json.dumps(root_obj.to_dict()).encode()
        tmp_trusted_set = TrustedMetadataSet(modified_root_data)
        # call root_update_finished when trusted root has expired
        with self.assertRaises(exceptions.ExpiredMetadataError):
            tmp_trusted_set.root_update_finished()


    def test_update_timestamp_new_timestamp_ver_below_trusted_ver(self):
        self._root_update_finished_and_update_timestamp()
        # new_timestamp.version < trusted_timestamp.version
        self.trusted_set.timestamp.signed.version = 2
        with self.assertRaises(exceptions.ReplayedMetadataError):
            self.trusted_set.update_timestamp(self.metadata["timestamp"])

    def test_update_timestamp_snapshot_ver_below_trusted_snapshot_ver(self):
        self._root_update_finished_and_update_timestamp()
        # new_timestamp.snapshot.version < trusted_timestamp.snapshot.version
        self.trusted_set.timestamp.signed.meta["snapshot.json"].version = 2
        with self.assertRaises(exceptions.ReplayedMetadataError):
            self.trusted_set.update_timestamp(self.metadata["timestamp"])

    def test_update_timestamp_snapshot_ver_below_trusted_snapshot_ver(self):
        self._root_update_finished_and_update_timestamp()
        # new_timestamp has expired
        timestamp = Metadata.from_bytes(self.metadata["timestamp"])
        timestamp.signed.expires = datetime(1970, 1, 1)
        self._sign_modified_obj("timestamp", timestamp)
        new_timestamp_byte_data = json.dumps(timestamp.to_dict()).encode()
        with self.assertRaises(exceptions.ExpiredMetadataError):
            self.trusted_set.update_timestamp(new_timestamp_byte_data)


    def test_update_snapshot_after_targets_updated(self):
        self._root_update_finished_and_update_timestamp()
        # cannot update snapshot after targets update completes or targets != None
        targets_obj = Metadata.from_bytes(self.metadata["targets"])
        self.trusted_set._trusted_set["targets"] = targets_obj
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_snapshot(self.metadata["snapshot"])

    def test_update_snapshot_cannot_verify_snapshot_with_threshold(self):
        self._root_update_finished_and_update_timestamp()
        # remove signature for snapshot from root data
        self.trusted_set.root.signed.roles["snapshot"].keyids = []
        with self.assertRaises(exceptions.UnsignedMetadataError):
            self.trusted_set.update_snapshot(self.metadata["snapshot"])
        self.trusted_set.root.signed.roles["snapshot"].threshold = 1

    def test_update_snapshot_version_different_timestamp_snapshot_version(self):
        self._root_update_finished_and_update_timestamp()
        # new_snapshot.version != trusted timestamp.meta["snapshot"].version
        self.trusted_set.timestamp.signed.meta["snapshot.json"].version = 2
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_snapshot(self.metadata["snapshot"])



    def test_update_snapshot_after_successful_update_new_snapshot_no_meta(self):
        self._update_all_besides_targets()
        # Test removing a meta_file in new_snapshot compared to the old snapshot
        snapshot_obj = Metadata.from_bytes(self.metadata["snapshot"])
        snapshot_obj.signed.meta = {}
        self._sign_modified_obj("snapshot", snapshot_obj)
        self.trusted_set.timestamp.signed.meta["snapshot.json"].hashes = None
        self.trusted_set.timestamp.signed.meta["snapshot.json"].length = None
        modified_snapshot_data = json.dumps(snapshot_obj.to_dict()).encode()
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_snapshot(modified_snapshot_data)

    def test_update_snapshot_after_succesfull_update_new_snapshot_meta_version_different(self):
        self._update_all_besides_targets()
        # snapshot.meta["project1"].version != new_snapshot.meta["project1"].version
        for metafile in self.trusted_set.snapshot.signed.meta.values():
            metafile.version += 1
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_snapshot(self.metadata["snapshot"])

    def test_update_snapshot_after_succesfull_expired_new_snapshot(self):
        self._update_all_besides_targets()
        # new_snapshot has expired
        snapshot_obj = Metadata.from_bytes(self.metadata["snapshot"])
        snapshot_obj.signed.expires = datetime(1970, 1, 1)
        self._sign_modified_obj("snapshot", snapshot_obj)
        self.trusted_set.timestamp.signed.meta["snapshot.json"].hashes = None
        self.trusted_set.timestamp.signed.meta["snapshot.json"].length = None
        modified_snapshot_data = json.dumps(snapshot_obj.to_dict()).encode()
        with self.assertRaises(exceptions.ExpiredMetadataError):
            self.trusted_set.update_snapshot(modified_snapshot_data)


    def test_update_targets_no_meta_in_snapshot(self):
        self._update_all_besides_targets()
        # remove meta information with information about targets from snapshot
        self.trusted_set.snapshot.signed.meta = {}
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_targets(self.metadata["targets"])

    def test_update_targets_hash_different_than_snapshot_meta_hash(self):
        self._update_all_besides_targets()
        # observed_hash != stored hash in snapshot meta for targets
        for target_path in self.trusted_set.snapshot.signed.meta.keys():
            self.trusted_set.snapshot.signed.meta[target_path].hashes = {"sha256": "b"}
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_targets(self.metadata["targets"])

    def test_update_targets_version_different_snapshot_meta_version(self):
        self._update_all_besides_targets()
        # new_delegate.signed.version != meta.version stored in snapshot
        for target_path in self.trusted_set.snapshot.signed.meta.keys():
            self.trusted_set.snapshot.signed.meta[target_path].version = 2
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_targets(self.metadata["targets"])

    def test_update_targets_expired_new_target(self):
        self._update_all_besides_targets()
        # new_delegated_target has expired
        targets_obj = Metadata.from_bytes(self.metadata["targets"])
        targets_obj.signed.expires = datetime(1970, 1, 1)
        self._sign_modified_obj("targets", targets_obj)
        modified_targets_data = json.dumps(targets_obj.to_dict()).encode()
        with self.assertRaises(exceptions.ExpiredMetadataError):
            self.trusted_set.update_targets(modified_targets_data)

    # TODO test updating over initial metadata (new keys, newer timestamp, etc)


if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
