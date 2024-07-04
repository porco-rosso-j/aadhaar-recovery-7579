// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {EnumerableGuardianMap, GuardianStorage, GuardianStatus} from "./EnumerableGuardianMap.sol";
import {IAnonAadhaarRecoveryManager} from "../interfaces/IAnonAadhaarRecoveryManager.sol";

library GuardianUtils {
    using EnumerableGuardianMap for EnumerableGuardianMap.UintToGuardianMap;
    using EnumerableGuardianMap for EnumerableGuardianMap.UintToGuardianMap;

    event AddedGuardian(address indexed account, uint indexed guardian);
    event RemovedGuardian(address indexed account, uint indexed guardian);
    event ChangedThreshold(address indexed account, uint256 threshold);

    error IncorrectNumberOfWeights();
    error ThresholdCannotBeZero();
    error InvalidGuardianAddress();
    error InvalidGuardianWeight();
    error AddressAlreadyGuardian();
    error ThresholdCannotExceedTotalWeight();
    error StatusCannotBeTheSame();
    error SetupNotCalled();
    error UnauthorizedAccountForGuardian();

    function getGuardianStorage(
        mapping(address => EnumerableGuardianMap.UintToGuardianMap)
            storage guardiansStorage,
        address account,
        uint guardian
    ) internal view returns (GuardianStorage memory) {
        return guardiansStorage[account].get(guardian);
    }

    function setupGuardians(
        mapping(address => IAnonAadhaarRecoveryManager.GuardianConfig)
            storage guardianConfigs,
        mapping(address => EnumerableGuardianMap.UintToGuardianMap)
            storage guardiansStorage,
        address account,
        uint[] memory guardians,
        uint256[] memory weights,
        uint256 threshold
    ) internal {
        uint256 guardianCount = guardians.length;

        if (guardianCount != weights.length) {
            revert IncorrectNumberOfWeights();
        }

        if (threshold == 0 && guardianCount > 0) {
            revert ThresholdCannotBeZero();
        }

        uint256 totalWeight = 0;
        for (uint256 i = 0; i < guardianCount; i++) {
            uint guardian = guardians[i];
            uint256 weight = weights[i];

            if (guardian == 0) {
                revert InvalidGuardianAddress();
            }

            // As long as weights are 1 or above, there will be enough total weight to reach the
            // required threshold. This is because we check the guardian count cannot be less
            // than the threshold and there is an equal amount of guardians to weights.
            if (weight == 0) {
                revert InvalidGuardianWeight();
            }

            GuardianStorage memory guardianStorage = guardiansStorage[account]
                .get(guardian);
            if (guardianStorage.status != GuardianStatus.NONE) {
                revert AddressAlreadyGuardian();
            }

            guardiansStorage[account].set({
                key: guardian,
                value: GuardianStorage(GuardianStatus.REQUESTED, weight)
            });
            totalWeight += weight;
        }

        if (threshold > totalWeight) {
            revert ThresholdCannotExceedTotalWeight();
        }

        guardianConfigs[account] = IAnonAadhaarRecoveryManager.GuardianConfig(
            guardianCount,
            totalWeight,
            threshold,
            true
        );
    }

    function updateGuardianStatus(
        mapping(address => EnumerableGuardianMap.UintToGuardianMap)
            storage guardiansStorage,
        address account,
        uint guardian,
        GuardianStatus newStatus
    ) internal {
        GuardianStorage memory guardianStorage = guardiansStorage[account].get(
            guardian
        );
        if (newStatus == guardianStorage.status) {
            revert StatusCannotBeTheSame();
        }

        guardiansStorage[account].set({
            key: guardian,
            value: GuardianStorage(newStatus, guardianStorage.weight)
        });
    }

    function addGuardian(
        mapping(address => EnumerableGuardianMap.UintToGuardianMap)
            storage guardiansStorage,
        mapping(address => IAnonAadhaarRecoveryManager.GuardianConfig)
            storage guardianConfigs,
        address account,
        uint guardian,
        uint256 weight
    ) internal {
        // Initialized can only be false at initialization.
        // Check ensures that setup function should be called first
        if (!guardianConfigs[account].initialized) {
            revert SetupNotCalled();
        }

        if (guardian == 0) {
            revert InvalidGuardianAddress();
        }

        GuardianStorage memory guardianStorage = guardiansStorage[account].get(
            guardian
        );

        if (guardianStorage.status != GuardianStatus.NONE) {
            revert AddressAlreadyGuardian();
        }

        if (weight == 0) {
            revert InvalidGuardianWeight();
        }

        guardiansStorage[account].set({
            key: guardian,
            value: GuardianStorage(GuardianStatus.REQUESTED, weight)
        });
        guardianConfigs[account].guardianCount++;
        guardianConfigs[account].totalWeight += weight;

        emit AddedGuardian(account, guardian);
    }

    function removeGuardian(
        mapping(address => EnumerableGuardianMap.UintToGuardianMap)
            storage guardiansStorage,
        mapping(address => IAnonAadhaarRecoveryManager.GuardianConfig)
            storage guardianConfigs,
        address account,
        uint guardian
    ) internal {
        IAnonAadhaarRecoveryManager.GuardianConfig
            memory guardianConfig = guardianConfigs[account];
        GuardianStorage memory guardianStorage = guardiansStorage[account].get(
            guardian
        );

        bool isGuardian = guardianStorage.status != GuardianStatus.NONE;
        if (!isGuardian) {
            revert UnauthorizedAccountForGuardian();
        }

        // Only allow guardian removal if threshold can still be reached.
        if (
            guardianConfig.totalWeight - guardianStorage.weight <
            guardianConfig.threshold
        ) {
            revert ThresholdCannotExceedTotalWeight();
        }

        guardiansStorage[account].remove(guardian);
        guardianConfigs[account].guardianCount--;
        guardianConfigs[account].totalWeight -= guardianStorage.weight;

        emit RemovedGuardian(account, guardian);
    }

    function removeAllGuardians(
        mapping(address => EnumerableGuardianMap.UintToGuardianMap)
            storage guardiansStorage,
        address account
    ) internal {
        guardiansStorage[account].removeAll(guardiansStorage[account].keys());
    }

    function changeThreshold(
        mapping(address => IAnonAadhaarRecoveryManager.GuardianConfig)
            storage guardianConfigs,
        address account,
        uint256 threshold
    ) internal {
        // Initialized can only be false at initialization.
        // Check ensures that setup function should be called first
        if (!guardianConfigs[account].initialized) {
            revert SetupNotCalled();
        }

        // Validate that threshold is smaller than the total weight.
        if (threshold > guardianConfigs[account].totalWeight) {
            revert ThresholdCannotExceedTotalWeight();
        }

        // There has to be at least one Account guardian.
        if (threshold == 0) {
            revert ThresholdCannotBeZero();
        }

        guardianConfigs[account].threshold = threshold;
        emit ChangedThreshold(account, threshold);
    }
}
