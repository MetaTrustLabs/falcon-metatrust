from .common.contract.locked_ether import LockedEther # need to concern about output
from .controlled_source.address_validation.arbitrary_send_eth import ArbitrarySendEth
from .common.operations.reentrancy_benign import ReentrancyBenign
from .common.operations.reentrancy_read_before_write import ReentrancyReadBeforeWritten
from .common.operations.reentrancy_eth import ReentrancyEth
from .common.operations.reentrancy_no_gas import ReentrancyNoGas
from .common.operations.reentrancy_events import ReentrancyEvent
from .codestyle.contract.unnecessary_reentrancy_lock import UnnecessaryReentrancyLock
from .codestyle.variable.possible_const_state_variables import ConstCandidateStateVars
from .controlled_source.access_control.tx_origin import TxOrigin
from .controlled_source.address_validation.controlled_delegatecall import ControlledDelegateCall
from .common.variables.state import StateShadowing
from .common.contract.builtin_symbols import BuiltinSymbolShadowing
from .common.contract.deprecated_calls import DeprecatedStandards
from .common.functions.unimplemented import UnimplementedFunctionDetection
from .common.variables.mapping_deletion import MappingDeletionDetection
from .common.variables.array_deletion import ArrayDeletionDetection
from .common.variables.array_length_assignment import ArrayLengthAssignment
from .codestyle.variable.similar_variables import SimilarVarsDetection
from .codestyle.statement.redundant_statements import RedundantStatements
from .chain_related.chain_feature.bad_prng import BadPRNG
from .common.operations.assert_state_change import AssertStateChange
from .compiler_bugs.storage_signed_integer_array import StorageSignedIntegerArray
from .compiler_bugs.storage_ABIEncoderV2_array import ABIEncoderV2Array
from .common.functions.array_by_reference import ArrayByReference
from .compiler_bugs.enum_conversion import EnumConversion
from .common.contract.multiple_constructor_schemes import MultipleConstructorSchemes
from .compiler_bugs.public_mapping_nested import PublicMappingNested
from .common.contract.reused_base_constructor import ReusedBaseConstructor
from .common.operations.missing_events_arithmetic import MissingEventsArithmetic
from .common.statements.write_after_write import WriteAfterWrite
from .common.statements.msg_value_in_loop import MsgValueInLoop
from .common.operations.delegatecall_in_loop import DelegatecallInLoop
# from .cryptography.usage.improper_sig_verify_func import ImproperSigVerify
from .cryptography.usage.sig_replay_attacks_protection import SigReplayProtectionDetection
from .cryptography.algorithm.sig_malleability import SigMalleability
from .common.functions.incorrect_constructor_name import IncorrectConstructorName
from .controlled_source.address_validation.arbitrary_send_erc20_no_permit import \
    ArbitrarySendErc20NoPermit
from .controlled_source.input_validation import InputValidation
from .common.operations.arbitrary_storage_location import ArbitraryStorageLocation
from .controlled_source.access_control.unprotected_ether_withdrawal import UnprotectedEtherWithdrawal
from .codestyle.function.function_init_state_variables import FunctionInitializedState
from .common.operations.hardcode_gas_amount import HardcodeGasAmount
from .common.statements.integer_underflow import IntegerUnderflow
from .common.statements.integer_overflow import IntegerOverflow
from .controlled_source.access_control.initialize_permission import InitializePermission
from .common.operations.fntype_var import FnTypeVarChecker
from .codestyle.contract.no_license import NoLicense
from .codestyle.statement.using_for_any_type import UsingForAnyTypeDetection
from .chain_related.api_usage.bytes_32 import Bytes32
from .common.contract.obsolete_function import ObsoleteUse
from .common.variables.constant_result import ConstantResult
from .codestyle.function.unused_event import UnusedEvent
from .codestyle.function.dead_code import DeadCode
from .common.variables.uninitialized_local_variables import UninitializedLocalVars
from .common.functions.unused_return_values import UnusedReturnValues
from .common.variables.predeclaration_usage_local import PredeclarationUsageLocal
from .common.contract.defi_action_nested import DeFiActionNested
from .codestyle.function.public_mint_burn import PublicMintBurnDetector
from .common.functions.modifier_unsafe import ModifierUnsafe
from .common.statements.address_zero_validation import MissingZeroAddressValidation
from .common.statements.tx_gas_price_warning import TxGaspriceWarning
from .common.functions.event_setter import EventSetter
from .common.functions.falsy_only_eoa_modifier import OnlyEOACheck
from .controlled_source.access_control.suicidal import Suicidal
from .common.operations.transfer_in_loop import TransferInLoop
from .common.operations.uncontrolled_resource_consumption import UnControlledResourceConsumption
from .common.functions.for_continue_increment import ForContinueIncrement
from .codestyle.statement.error_msg import ErrorMsg
from .codestyle.statement.boolean_constant_equality import BooleanEquality
from .codestyle.function.void_function import VoidFunction
from .codestyle.contract.unnecessary_reentrancy_guard import UnnecessaryReentrancyGuard
from .codestyle.contract.unnecessary_public_function_modifier import UnnecessaryPublicFunctionModifier
from .common.variables.state_var_uninitialized import StateVariableNotInitialized
# from .common.functions.unprotected_setter import UnprotectedSetter
# =======Halt for MetaScore=======
# from .codestyle.statement.incorrect_strict_equality import IncorrectStrictEquality
# from .common.operations.dos_with_failed_call import DosWithFailedCallDetection

# from .controlled_source.address_validation.call_inject import CallInject
# from .common.variables.local import LocalShadowing


# from .controlled_source.address_validation.caller_contractcheck import CallerContractChecker
# from .codestyle.contract.naming_convention import NamingConvention
# from .chain_related.api_usage.encode_packed import EncodePacked

# from .codestyle.variable.missing_mutability import MissingMutability
# from .common.statements.type_based_tautology import TypeBasedTautology
# from .common.statements.divide_before_multiply import DivideBeforeMultiply
# from .controlled_source.access_control.unprotected_upgradeable import UnprotectedUpgradeable
# from .codestyle.contract.name_reused import NameReused

# from .codestyle.contract.constant_pragma import ConstantPragma


# =======Move to LINT=======
# from .common.operations.assembly import Assembly
# from .common.variables.reuse_state_variable import ReuseStatevariables
# from .common.functions.function_visibility import FunctionVisibility
# from .chain_related.chain_feature.block_timestamp import Timestamp
# from .codestyle.function.void_constructor import VoidConstructor
# from .codestyle.variable.unused_vars import UnusedVars
# from .common.functions.modifier import ModifierDefaultDetection
# from .common.statements.unary import IncorrectUnaryExpressionDetection
# from .common.contract.incorrect_inheritance_order import IncorrectInheritanceOrderChecker
# from .codestyle.contract.order_layout import OrderLayoutDetection
from .codestyle.contract.version_only import VersionOnly
# from .common.variables.uninitialized_function_ptr_in_constructor import UninitializedFunctionPtrsConstructor
# from .common.variables.magic_number import MagicNumber