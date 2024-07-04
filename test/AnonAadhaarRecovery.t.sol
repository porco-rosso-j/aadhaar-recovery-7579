import {console2} from "forge-std/console2.sol";
import {ModuleKitHelpers, ModuleKitUserOp} from "modulekit/ModuleKit.sol";
import {MODULE_TYPE_EXECUTOR} from "modulekit/external/ERC7579.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {GuardianStorage, GuardianStatus} from "src/libraries/EnumerableGuardianMap.sol";
import {IEmailRecoveryManager} from "src/interfaces/IEmailRecoveryManager.sol";
