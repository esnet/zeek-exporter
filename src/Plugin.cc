#include <chrono>
#include <stack>

#include <prometheus/exposer.h>
#include <prometheus/registry.h>

#include <ZeekString.h>

#include <Event.h>
#include <Func.h>
#include <Reporter.h>

#include "Plugin.h"

namespace plugin { namespace ESnet_Zeek_Exporter { Plugin plugin; } }

using namespace plugin::ESnet_Zeek_Exporter;

Plugin::Plugin() {
    // Constructor
    zeek_total_cpu_time_seconds.Add({{"type", "PluginInstantiation"}}, (double) clock()/CLOCKS_PER_SEC);
}

void Plugin::InitPreScript() {
    // First-stage initializion
    zeek_total_cpu_time_seconds.Add({{"type", "InitPreScript"}}, (double) clock()/CLOCKS_PER_SEC);
}

void Plugin::InitPostScript()
{
    // Third-stage initialization
    zeek_total_cpu_time_seconds.Add({{"type", "InitPostScript"}}, (double) clock()/CLOCKS_PER_SEC);

    const char* bind_ip = BifConst::Exporter::bind_address->AsAddr().AsString().c_str();
    const uint32_t bind_port = BifConst::Exporter::bind_port->Port();

    try
    {
        exposer = std::make_shared<prometheus::Exposer>(fmt("%s:%d", bind_ip, bind_port));
        exposer->RegisterCollectable(registry);
        zeek_start_time_seconds.Add({{"type", "plugin_start_time"}}).Increment(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    }
    catch ( const std::exception& )
    {
        reporter->Warning("%s failed to bind to %s:%d", plugin_name, bind_ip, bind_port);
    }
}

plugin::Configuration Plugin::Configure()
{
    plugin::Configuration config;
    config.name = plugin_name;
    config.description = "Prometheus exporter for Zeek";
    config.version.major = 0;
    config.version.minor = 2;

    // We want to track functions even if they get handled by another hook, so high priority here
    EnableHook(HOOK_CALL_FUNCTION, 1000001);

    // Default priority is fine here
    EnableHook(META_HOOK_PRE);
    EnableHook(META_HOOK_POST);

    // We want to track these *after* other plugins get a chance to handle them, so low priority
    EnableHook(HOOK_LOG_WRITE, -20);

    return config;
}

void Plugin::AddlArgumentPopulation(const char * name, val_list* args, std::map<std::string, std::string>& labels) {
    int arg_offset = -1;
    int addl_offset = -1;

    for (auto & arg_event : arg_events)
    {
        if ( strcmp(name, arg_event.first.c_str()) == 0 )
        {
            arg_offset = std::get<0>(arg_event.second);
            addl_offset = std::get<1>(arg_event.second);
            break;
        }
    }

    if ( arg_offset >= 0  && args->length() > arg_offset && IsString((*args)[arg_offset]->Type()->Tag()) )
    {
        const char* arg_str = (*args)[arg_offset]->AsString()->CheckString();
        if ( strlen(arg_str) )
            labels.insert({"arg", arg_str});
    }

    if ( addl_offset >= 0 && args->length() > addl_offset && IsString((*args)[addl_offset]->Type()->Tag()) )
    {
        const char* addl_str = (*args)[addl_offset]->AsString()->CheckString();
        if ( strlen(addl_str) )
            labels.insert({"addl", addl_str});
    }
}


std::pair<bool, Val*> Plugin::HookCallFunction(const Func* func, Frame* frame, val_list* args)
    {
    // Without this, we'll recurse indefinitely
    if ( func == current_func ) {
        return {false, NULL};
    }
    // Since we're handling the function call, we need to increase the ref count on the arguments
    for ( int i = 0; i < args->length(); ++i )
        Ref((*args)[i]);

    // Set our indicators, measure the runtime, and call the function.
    own_handler = true;
    current_func = func;
    auto start = std::chrono::steady_clock::now();
    Val* result = func->Call(args, frame);
    auto stop = std::chrono::steady_clock::now();
    current_func = nullptr;
    own_handler = false;

    // We create a new variable, because children will increase this
    size_t my_func_depth = func_depth;

    std::map<std::string, std::string> labels;

    switch ( func->Flavor() )
    {
        case FUNC_FLAVOR_FUNCTION:
            labels = {{"function_type", func->GetKind() ? "built-in function" : "script-land function"}};
            break;
        case FUNC_FLAVOR_EVENT:
            labels = {{"function_type", "event"}};
            break;
        case FUNC_FLAVOR_HOOK:
            labels = {{"function_type", "hook"}};
            break;
        default:
            labels = {{"function_type", "unknown"}};
            break;
    }

    std::chrono::microseconds duration;

    auto last_function_duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);

    // We subtract this in the post hook handler from the duration of the hook. We need to add this to a stack
    // because the child post hook will be called before ours.
    func_durations.push(last_function_duration);

    // We need to measure how long any child functions take.
    double children_duration = 0.0;
    // If our vector is larger than our current depth, we have some children we must account for.
    if ( child_func_durations.size() > ( my_func_depth + 1 ) )
    {
        children_duration = child_func_durations.back();
        child_func_durations.pop_back();
    }

    // We don't track this for top-level functions, since there's no point.
    if ( my_func_depth )
    {
        // Initialize this to the right depth
        while ( child_func_durations.size() <= my_func_depth )
            child_func_durations.push_back(0.0);

        child_func_durations[my_func_depth] += last_function_duration.count();
    }

    // We keep a running total, without function name & caller labels
    zeek_function_calls_total.Add(labels).Increment();
    zeek_cpu_time_per_script_seconds.Add({{"script", func->GetLocationInfo()->filename}}).Increment(last_function_duration.count());
    zeek_cpu_time_per_function_type_seconds.Add(labels).Increment((last_function_duration.count() - children_duration) / 1000000.0);

    // Now we add our metadata and store it again, with the label(s)
    const char * name = func->Name();
    labels.insert({"name", func->Name()});

    // Grab some values for select events. Only bother if we have arguments, and if it's an event
    if ( args->length() && func->Flavor() == FUNC_FLAVOR_EVENT )
    {
        start = std::chrono::steady_clock::now();
        AddlArgumentPopulation(name, args, labels);
        stop = std::chrono::steady_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        zeek_hook_cpu_time_seconds.Add({{"plugin", plugin_name}, {"hook", "AddlArgumentPopulation"}}).Increment(duration.count() / 1000000.0);
    }

    if ( lineage.size() > 1) {
        // We're lineage[lineage.size()-1], parent is size()-2
        labels.insert({"function_caller", lineage[lineage.size() - 2]});
    }
    zeek_function_calls_total.Add(labels).Increment();
    zeek_cpu_time_per_function_seconds.Add(labels).Increment(last_function_duration.count() / 1000000.0);
    zeek_absolute_cpu_time_per_function_seconds.Add(labels).Increment((last_function_duration.count() - children_duration) / 1000000.0);

    // We update the list of functions we want some arguments for.
    if ( strcmp(name, "Exporter::update_arg_functions") == 0 && args->length() == 3 )
    {
        int arg_val = (*args)[1]->AsInt();
        int addl_val = (*args)[2]->AsInt();
        if ( arg_val >= 0 || addl_val >= 0 )
            arg_events.insert({std::string((*args)[0]->AsString()->CheckString()), std::make_tuple(arg_val, addl_val)});
    }
    return {true, result};
}

bool Plugin::HookLogWrite(const std::string& writer, const std::string& filter, const logging::WriterBackend::WriterInfo& info, int num_fields, const threading::Field* const* fields, threading::Value** vals)
{
    std::map<std::string, std::string> labels = {{"type", "log_write"}, {"writer", writer}, {"filter", filter}};
    if ( info.path )
        labels.insert({"path", info.path});

    zeek_log_writes_total.Add(labels).Increment();
    return true;
}


void Plugin::MetaHookPre(HookType hook, const HookArgumentList& args)
{
    // This hook is our most common entrypoint, so we track overall CPU time here
    zeek_total_cpu_time_seconds.Add({{"type", "cpu_time"}}).Set((double) clock()/CLOCKS_PER_SEC);

    if ( hook == HOOK_LOG_WRITE )
        log_hook_start = std::chrono::steady_clock::now();
    else if ( hook == HOOK_CALL_FUNCTION )
    {
        func_hook_starts.push(std::chrono::steady_clock::now());
        const Func* func = args.front().AsFunc();
        if ( func != current_func )
        {
            // Increase the depth, and append it to the lineage vector
            func_depth++;
            lineage.push_back(func->Name());
        }
    }
    else
        other_hook_start = std::chrono::steady_clock::now();
}

void Plugin::MetaHookPost(HookType hook, const HookArgumentList& args, HookArgument result)
{
    // Grab the timestamp first, for increased accuracy
    auto hook_stop = std::chrono::steady_clock::now();
    std::map<std::string, std::string> labels = {{"hook", hook_name(hook)}};

    // The function call timing is rather complex, due to recursion. Handle the easy log writes first.
    if ( hook == HOOK_LOG_WRITE )
    {
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(hook_stop - log_hook_start);
        zeek_hook_cpu_time_seconds.Add(labels).Increment(duration.count() / 1000000.0);
        return;
    }

    // This is a hook we don't handle, but someone else might
    if ( hook != HOOK_CALL_FUNCTION )
    {
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(hook_stop - other_hook_start);
        zeek_hook_cpu_time_seconds.Add(labels).Increment(duration.count() / 1000000.0);
        return;
    }

    // Grab the last function hook start time off the stack, and calculate the duration
    double duration = std::chrono::duration_cast<std::chrono::microseconds>(hook_stop - func_hook_starts.top()).count();
    func_hook_starts.pop();

    const Func* func = args.front().AsFunc();
    // This is another plugin's hook handler
    if ( ! own_handler && func == current_func)
    {
        labels.insert({"plugin", "unknown"});
    }
    else {
        if ( func == current_func )
        {
            // This is our inner handler. The next handler to run will not be ours.
            own_handler = false;
            labels.insert({{"plugin", plugin_name}, {"handler", "inner"}});
        }
        else
        {
            // Outer handler
            labels.insert({{"plugin", plugin_name}, {"handler", "outer"}});

            // The outer handler duration is the duration of the hook, minus the execution time of the function.
            duration -= func_durations.top().count();
            func_durations.pop();

            // We returned, so adjust the lineage and function depth to reflect that.
            lineage.pop_back();
            func_depth--;
        }
    }

    zeek_hooks_total.Add(labels).Increment();
    zeek_hook_cpu_time_seconds.Add(labels).Increment(duration / 1000000);
}
